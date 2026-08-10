package mysql

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMariaDBCapabilityValues(t *testing.T) {
	require.Equal(t, CLIENT_LONG_PASSWORD, CLIENT_MYSQL)
	require.Equal(t, MariaDBCapability(1<<0), MARIADB_CLIENT_PROGRESS)
	require.Equal(t, MariaDBCapability(1<<1), MARIADB_CLIENT_COM_MULTI)
	require.Equal(t, MariaDBCapability(1<<2), MARIADB_CLIENT_STMT_BULK_OPERATIONS)
	require.Equal(t, MariaDBCapability(1<<3), MARIADB_CLIENT_EXTENDED_METADATA)
	require.Equal(t, MariaDBCapability(1<<4), MARIADB_CLIENT_CACHE_METADATA)
	require.Equal(t, MariaDBCapability(1<<5), MARIADB_CLIENT_BULK_UNIT_RESULTS)
}
