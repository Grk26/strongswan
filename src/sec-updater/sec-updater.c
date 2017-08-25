/*
 * Copyright (C) 2012-2017 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <library.h>
#include <utils/debug.h>

typedef enum sec_update_state_t sec_update_state_t;

enum sec_update_state_t {
	SEC_UPDATE_STATE_BEGIN_PACKAGE,
	SEC_UPDATE_STATE_VERSION,
	SEC_UPDATE_STATE_END_PACKAGE
};

typedef struct stats_t stats_t;

struct stats_t {
	time_t release;
	int product;
	int packages;
	int new_packages;
	int new_versions;
};

/**
 * global debug output variables
 */
static int debug_level = 1;
static bool stderr_quiet = TRUE;

/**
 * sec_update dbg function
 */
static void sec_update_dbg(debug_t group, level_t level, char *fmt, ...)
{
	int priority = LOG_INFO;
	char buffer[8192];
	char *current = buffer, *next;
	va_list args;

	if (level <= debug_level)
	{
		if (!stderr_quiet)
		{
			va_start(args, fmt);
			vfprintf(stderr, fmt, args);
			fprintf(stderr, "\n");
			va_end(args);
		}

		/* write in memory buffer first */
		va_start(args, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);

		/* do a syslog with every line */
		while (current)
		{
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			syslog(priority, "%s\n", current);
			current = next;
		}
	}
}

/**
 * atexit handler to close everything on shutdown
 */
static void cleanup(void)
{
	closelog();
	library_deinit();
}

static void usage(void)
{
	printf("Parses package information files from Debian/Ubuntu repositories and\n");
	printf("stores the extracted information in the database used by the OS IMV.\n\n");
	printf("ipsec sec_update --product <name> --file <filename> [--security]\n\n");
	printf("  --help               print usage information\n");
	printf("  --product <name>     name of the Debian/Ubuntu release, as stored in the DB\n");
	printf("  --file <filename>    package information file to parse\n");
	printf("  --security           set this when parsing a file with security updates\n");
	printf("\n");
}

/**
 * Update the package database
 */
static bool update_database(database_t *db, char *package, char *version,
							bool security, stats_t *stats)
{
	int pid = 0, vid = 0, count = 0, sec_flag;
	bool first = TRUE, found = FALSE, set_sec_flag = FALSE;
	char *release;
	enumerator_t *e;

	/* increment package count */
	stats->packages++;

	/* check if package is already in database */
	e = db->query(db, "SELECT id FROM packages WHERE name = ?",
					  DB_TEXT, package, DB_INT);
	if (!e)
	{
		return FALSE;
	}
	if (!e->enumerate(e, &pid))
	{
		pid = 0;
	}
	e->destroy(e);

	if (!pid)
	{
		/*if (db->execute(db, &pid, "INSERT INTO packages (name) VALUES (?)",
						DB_TEXT, package) != 1)
		{
			fprintf(stderr, "could not store package '%s' to database\n",
							 package);
			return FALSE;
		}
		fprintf(stderr, "  %s\n", package); */
		stats->new_packages++;
	}
	else
	{
		/* check if package version is already in database */
		e = db->query(db,
			"SELECT id, release, security FROM versions "
			"WHERE product = ? AND package = ?",
			 DB_INT, stats->product,  DB_INT, pid, DB_INT, DB_TEXT, DB_INT);
		if (!e)
		{
			return FALSE;
		}
		while (e->enumerate(e, &vid, &release, &sec_flag))
		{
			char command[BUF_LEN];
			char found_char = ' ';

			if (first)
			{
				printf("%s\n", package);
				first = FALSE;
			}
			if (streq(version, release))
			{
				found = TRUE;
				found_char = '*';
			}
			else if (security)
			{
				 snprintf(command, BUF_LEN, "dpkg --compare-versions %s lt %s",
											 release, version);
				if (system(command) == 0)
				{
					found_char = '!';
				}
			}
			printf("  %c%s %s\n", found_char , sec_flag ? "s" : " ", release);
		}
		e->destroy(e);

		if (!found && !first)
		{
			printf("  +  %s\n", version);
			stats->new_versions++;
		}
	}

	return TRUE;
}

/**
 * Process a package file and store updates in the database
 */
static void process_packages(char *filename, char *product, bool security)
{
	char *uri, line[BUF_LEN], *pos, *package = NULL, *version = NULL;
	sec_update_state_t state;
	enumerator_t *e;
	database_t *db;
	int pid;
	FILE *file;
	stats_t stats;
	bool success;

	/* initialize statistics */
	memset(&stats, 0x00, sizeof(stats_t));

	/* Set release date to current time */
	stats.release = time(NULL);

	/* opening package file */
	printf("loading\"%s\"\n", filename);
	file = fopen(filename, "r");
	if (!file)
	{
		fprintf(stderr, "could not open \"%s\"\n", filename);
		exit(EXIT_FAILURE);
	}

	/* connect package database */
	uri = lib->settings->get_str(lib->settings, "sec-update.database", NULL);
	if (!uri)
	{
		fprintf(stderr, "database URI sec-update.database not set\n");
		fclose(file);
		exit(EXIT_FAILURE);
	}
	db = lib->db->create(lib->db, uri);
	if (!db)
	{
		fprintf(stderr, "could not connect to database '%s'\n", uri);
		fclose(file);
		exit(EXIT_FAILURE);
	}

	/* check if product is already in database */
	e = db->query(db, "SELECT id FROM products WHERE name = ?",
				  DB_TEXT, product, DB_INT);
	if (e)
	{
		if (e->enumerate(e, &pid))
		{
			stats.product = pid;
		}
		e->destroy(e);
	}
	if (!stats.product)
	{
		if (db->execute(db, &pid, "INSERT INTO products (name) VALUES (?)",
						DB_TEXT, product) != 1)
		{
			fprintf(stderr, "could not store product '%s' to database\n",
							 product);
			fclose(file);
			db->destroy(db);
			exit(EXIT_FAILURE);
		}
		stats.product = pid;
	}

	state = SEC_UPDATE_STATE_BEGIN_PACKAGE;

	while (fgets(line, sizeof(line), file))
	{
		/* set read pointer to beginning of line */
		pos = line;

		switch (state)
		{
			case SEC_UPDATE_STATE_BEGIN_PACKAGE:
				pos = strstr(pos, "Package: ");
				if (!pos)
				{
					continue;
				}
				pos += 9;
				package = pos;
				pos = strchr(pos, '\n');
				if (pos)
				{
					package = strndup(package, pos - package);
					state = SEC_UPDATE_STATE_VERSION;
				}
				break;
			case SEC_UPDATE_STATE_VERSION:
				pos = strstr(pos, "Version: ");
				if (!pos)
				{
					continue;
				}
				pos += 9;
				version = pos;
				pos = strchr(pos, '\n');
				if (pos)
				{
					version = strndup(version, pos - version);
					state = SEC_UPDATE_STATE_END_PACKAGE;
				}
				break;
			case SEC_UPDATE_STATE_END_PACKAGE:
				if (*pos != '\n')
				{
					continue;
				}
				success = update_database(db, package, version, security, &stats);
				free(package);
				free(version);
				if (!success)
				{
					fclose(file);
					db->destroy(db);
					exit(EXIT_FAILURE);
				}
				state = SEC_UPDATE_STATE_BEGIN_PACKAGE;
		}
	}
	switch (state)
	{
		case SEC_UPDATE_STATE_END_PACKAGE:
			free(version);
			/* fall-through */
		case SEC_UPDATE_STATE_VERSION:
			free(package);
			break;
		default:
			break;
	}
	fclose(file);
	db->destroy(db);

	printf("processed %d packages, %d new packages, %d new versions\n",
			stats.packages, stats.new_packages, stats.new_versions);
}

static void do_args(int argc, char *argv[])
{
	char *filename = NULL, *product = NULL;
	bool security = FALSE;

	/* reinit getopt state */
	optind = 0;

	while (TRUE)
	{
		int c;

		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "file", required_argument, NULL, 'f' },
			{ "product", required_argument, NULL, 'p' },
			{ "security", no_argument, NULL, 's' },
			{ 0,0,0,0 }
		};

		c = getopt_long(argc, argv, "", long_opts, NULL);
		switch (c)
		{
			case EOF:
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'f':
				filename = optarg;
				continue;
			case 'p':
				product = optarg;
				continue;
			case 's':
				security = TRUE;
				continue;
		}
		break;
	}

	if (filename && product)
	{
		process_packages(filename, product, security);
	}
	else
	{
		usage();
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	/* enable attest debugging hook */
	dbg = sec_update_dbg;
	openlog("sec-update", 0, LOG_DEBUG);

	atexit(cleanup);

	/* initialize library */
	if (!library_init(NULL, "sec-update"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "sec-update.load", "sqlite")))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	do_args(argc, argv);

	exit(EXIT_SUCCESS);
}

