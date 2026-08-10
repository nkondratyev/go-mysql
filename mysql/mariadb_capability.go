package mysql

// CLIENT_MYSQL is the MariaDB name for CLIENT_LONG_PASSWORD.
const CLIENT_MYSQL = CLIENT_LONG_PASSWORD

// MariaDBCapability represents a MariaDB-specific capability extension flag.
type MariaDBCapability uint32

const (
	MARIADB_CLIENT_PROGRESS MariaDBCapability = 1 << iota
	// MARIADB_CLIENT_COM_MULTI is deprecated and retained to preserve capability bit positions.
	MARIADB_CLIENT_COM_MULTI
	MARIADB_CLIENT_STMT_BULK_OPERATIONS
	MARIADB_CLIENT_EXTENDED_METADATA
	MARIADB_CLIENT_CACHE_METADATA
	MARIADB_CLIENT_BULK_UNIT_RESULTS
)
