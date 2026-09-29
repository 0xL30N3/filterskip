/*
 * DawgFilter configuration.
 *
 * Two modes, selected at compile time:
 *   make                    -> port-based filtering (classic)
 *   make PROC_MODE=1        -> process-based filtering (defines DAWG_PROC_FILTER)
 *
 * In process mode the module only lets traffic through for sockets that were
 * created (socket()/accept()/...) by a binary listed in ALLOWED_BINS below.
 * Paths must be the REAL absolute path of the executable (it is resolved at
 * module load via kern_path() and compared by inode identity, so a renamed or
 * deleted-and-replaced binary will NOT match until the module is reloaded).
 */

#ifdef DAWG_PROC_FILTER

/* Binaries allowed to create network sockets. Everything else gets DEFAULT_RULE. */
static const char *const ALLOWED_BINS[] = {
	"/usr/sbin/httpd",
	"/usr/sbin/nginx",
};

#else /* ---- port-based mode ---- */

static const int IN_PORTS_TCP[] = {22, 80, 8080};
static const int OUT_PORTS_TCP[] = {6767, 9000, 8000, 53, 443, 80};
static const int IN_PORTS_UDP[] = {22, 80, 8080};
static const int OUT_PORTS_UDP[] = {6767, 9000, 8000, 53, 443, 80};

#endif /* DAWG_PROC_FILTER */

static unsigned int DEFAULT_RULE = NF_DROP;
