package client

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/pingcap/tidb/pkg/parser/charset"
	"github.com/stretchr/testify/require"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
)

func TestConnGenAttributes(t *testing.T) {
	c := &Conn{
		// example data from
		// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse41
		attributes: map[string]string{
			"_os":             "debian6.0",
			"_client_name":    "libmysql",
			"_pid":            "22344",
			"_client_version": "5.6.6-m9",
			"_platform":       "x86_64",
			"foo":             "bar",
		},
	}

	data := c.genAttributes()

	// the order of the attributes map cannot be guaranteed so to test the content
	// of the attribute data we need to check its partial contents

	require.Len(t, data, 98)
	require.Equal(t, byte(0x61), data[0])

	for k, v := range c.attributes {
		fixt := append(mysql.PutLengthEncodedString([]byte(k)), mysql.PutLengthEncodedString([]byte(v))...)
		require.Subset(t, data, fixt)
	}
}

func TestConnCollation(t *testing.T) {
	collations := []string{
		"big5_chinese_ci",
		"utf8_general_ci",
		"utf8mb4_0900_ai_ci",
		"utf8mb4_de_pb_0900_ai_ci",
		"utf8mb4_ja_0900_as_cs",
		"utf8mb4_0900_bin",
		"utf8mb4_zh_pinyin_tidb_as_cs",
	}

	// test all supported collations by calling writeAuthHandshake() and reading the bytes
	// sent to the server to ensure the collation id is set correctly
	for _, c := range collations {
		collation, err := charset.GetCollationByName(c)
		require.NoError(t, err)
		handshakeResponse := readAuthResponse(t, func(c *Conn) {
			c.collation = collation.Name
		})

		// validate the collation id is set correctly
		// if the collation ID is <= 255 the collation ID is stored in the 12th byte
		if collation.ID <= 255 {
			require.Equal(t, byte(collation.ID), handshakeResponse[12])
		} else {
			// if the collation ID is > 255 the collation ID should just be the lower-8 bits
			require.Equal(t, byte(collation.ID&0xff), handshakeResponse[12])
		}

		// the 13th byte should always be 0x00
		require.Equal(t, byte(0x00), handshakeResponse[13])

		// sanity check: validate the 22 bytes of filler with value 0x00 are set correctly
		for i := 13; i < 13+23; i++ {
			require.Equal(t, byte(0x00), handshakeResponse[i])
		}

		// and finally the username
		username := string(handshakeResponse[36:40])
		require.Equal(t, "test", username)
	}
}

func TestConnReadInitialHandshakeMariaDBCapabilities(t *testing.T) {
	capability := mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION | mysql.CLIENT_PLUGIN_AUTH
	mariadbCapabilities := mysql.MARIADB_CLIENT_PROGRESS |
		mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS |
		mysql.MARIADB_CLIENT_CACHE_METADATA

	c := readInitialHandshake(t, initialHandshakePacket(capability, mariadbCapabilities))

	require.Equal(t, mariadbCapabilities, c.mariadbServerCapabilities)
	require.Equal(t, "11.8.8-MariaDB", c.serverVersion)
	require.Equal(t, mysql.AUTH_NATIVE_PASSWORD, c.authPluginName)
	require.Equal(t, []byte("12345678abcdefghijkl"), c.salt)
}

func TestConnReadInitialHandshakeIgnoresMariaDBCapabilitiesForMySQL(t *testing.T) {
	capability := mysql.CLIENT_MYSQL | mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION | mysql.CLIENT_PLUGIN_AUTH

	c := readInitialHandshake(t, initialHandshakePacket(capability, mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS))

	require.Zero(t, c.mariadbServerCapabilities)
	require.Equal(t, mysql.AUTH_NATIVE_PASSWORD, c.authPluginName)
}

func TestConnWriteAuthHandshakeCapabilities(t *testing.T) {
	t.Run("MySQL", func(t *testing.T) {
		response := readAuthResponse(t, nil)

		capability := binary.LittleEndian.Uint32(response[4:8])
		require.NotZero(t, capability&mysql.CLIENT_MYSQL)
		require.Equal(t, []byte{0, 0, 0, 0}, response[32:36])
	})

	t.Run("MariaDB", func(t *testing.T) {
		response := readAuthResponse(t, func(c *Conn) {
			c.capability &^= mysql.CLIENT_MYSQL
			c.mariadbServerCapabilities = mysql.MARIADB_CLIENT_PROGRESS |
				mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS
			require.NoError(t, WithMariaDBCapabilities(
				mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS,
				mysql.MARIADB_CLIENT_CACHE_METADATA,
			)(c))
		})

		capability := binary.LittleEndian.Uint32(response[4:8])
		require.Zero(t, capability&mysql.CLIENT_MYSQL)
		require.Equal(t,
			mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS,
			mysql.MariaDBCapability(binary.LittleEndian.Uint32(response[32:36])),
		)
		require.Equal(t, "test", string(response[36:40]))
	})
}

func TestWithMariaDBCapabilities(t *testing.T) {
	c := &Conn{
		mariadbServerCapabilities: mysql.MARIADB_CLIENT_PROGRESS |
			mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS,
	}

	require.False(t, c.HasMariaDBCapability(mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS))
	require.False(t, c.HasNegotiatedMariaDBCapability(mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS))

	require.NoError(t, WithMariaDBCapabilities(
		mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS,
		mysql.MARIADB_CLIENT_CACHE_METADATA,
	)(c))

	require.True(t, c.HasMariaDBCapability(mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS))
	require.True(t, c.HasNegotiatedMariaDBCapability(mysql.MARIADB_CLIENT_STMT_BULK_OPERATIONS))
	require.True(t, c.HasMariaDBCapability(mysql.MARIADB_CLIENT_CACHE_METADATA))
	require.False(t, c.HasNegotiatedMariaDBCapability(mysql.MARIADB_CLIENT_CACHE_METADATA))
}

func readAuthResponse(t *testing.T, configure func(*Conn)) []byte {
	t.Helper()

	server, client := net.Pipe()
	c := &Conn{
		Conn:           packet.NewConn(client),
		capability:     mysql.CLIENT_MYSQL,
		authPluginName: "mysql_native_password",
		user:           "test",
		db:             "test",
		password:       "test",
		proto:          "tcp",
		salt:           []byte("123456781234567812345678"),
	}
	if configure != nil {
		configure(c)
	}

	errCh := make(chan error, 1)
	go func() {
		err := c.writeAuthHandshake()
		if closeErr := c.Close(); err == nil {
			err = closeErr
		}
		errCh <- err
	}()

	response, err := io.ReadAll(server)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
	require.NoError(t, server.Close())
	return response
}

func readInitialHandshake(t *testing.T, data []byte) *Conn {
	t.Helper()

	server, client := net.Pipe()
	c := &Conn{Conn: packet.NewConn(client)}
	errCh := make(chan error, 1)
	go func() {
		serverConn := packet.NewConn(server)
		err := serverConn.WritePacket(data)
		if closeErr := serverConn.Close(); err == nil {
			err = closeErr
		}
		errCh <- err
	}()

	require.NoError(t, c.readInitialHandshake())
	require.NoError(t, <-errCh)
	require.NoError(t, c.Close())
	return c
}

func initialHandshakePacket(capability uint32, mariadbCapabilities mysql.MariaDBCapability) []byte {
	data := make([]byte, 4, 128)
	data = append(data, mysql.ClassicProtocolVersion)
	data = append(data, "11.8.8-MariaDB"...)
	data = append(data, 0)
	data = append(data, mysql.Uint32ToBytes(1)...)
	data = append(data, "12345678"...)
	data = append(data, 0)
	data = append(data, byte(capability), byte(capability>>8))
	data = append(data, byte(mysql.DEFAULT_COLLATION_ID))
	data = append(data, byte(mysql.SERVER_STATUS_AUTOCOMMIT), byte(mysql.SERVER_STATUS_AUTOCOMMIT>>8))
	data = append(data, byte(capability>>16), byte(capability>>24))
	data = append(data, 21)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, mysql.Uint32ToBytes(uint32(mariadbCapabilities))...)
	data = append(data, "abcdefghijkl"...)
	data = append(data, 0)
	data = append(data, mysql.AUTH_NATIVE_PASSWORD...)
	data = append(data, 0)
	return data
}
