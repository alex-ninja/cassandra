/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cassandra.db.virtual;

import com.google.common.collect.ImmutableList;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.datastax.driver.core.EndPoint;
import com.datastax.driver.core.PlainTextAuthProvider;
import org.apache.cassandra.SchemaLoader;
import org.apache.cassandra.auth.AuthTestUtils;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.PasswordAuthenticator;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.CQLTester;
import org.apache.cassandra.cql3.UntypedResultSet;

import static org.apache.cassandra.auth.AuthTestUtils.ROLE_A;
import static org.apache.cassandra.auth.AuthTestUtils.ROLE_B;

public class CredentialsCacheTableTest extends CQLTester
{
    private static final String KS_NAME = "vts";
    private static AuthTestUtils.LocalPasswordAuthenticator passwordAuthenticator;
    private static String hashedPasswordRoleA;
    private static String hashedPasswordRoleB;

    private CredentialsCacheTable table;

    @BeforeClass
    public static void setUpClass()
    {
        // high value is used for convenient debugging
        DatabaseDescriptor.setPermissionsValidity(20_000);

        CQLTester.setUpClass();
        AuthTestUtils.LocalCassandraRoleManager roleManager = new AuthTestUtils.LocalCassandraRoleManager();
        passwordAuthenticator = new AuthTestUtils.LocalPasswordAuthenticator();
        SchemaLoader.setupAuth(roleManager,
                passwordAuthenticator,
                new AuthTestUtils.LocalCassandraAuthorizer(),
                new AuthTestUtils.LocalCassandraNetworkAuthorizer());

        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_A, AuthTestUtils.getLoginRoleOprions());
        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_B, AuthTestUtils.getLoginRoleOprions());

        hashedPasswordRoleA = passwordAuthenticator.queryHashedPassword(ROLE_A.getRoleName());
        hashedPasswordRoleB = passwordAuthenticator.queryHashedPassword(ROLE_B.getRoleName());
    }

    @Before
    public void config()
    {
        table = new CredentialsCacheTable(KS_NAME);
        VirtualKeyspaceRegistry.instance.register(new VirtualKeyspace(KS_NAME, ImmutableList.of(table)));

        // ensure nothing keeps cached between tests
        PasswordAuthenticator.getCredentialsCache().invalidate();
    }

    @AfterClass
    public static void tearDownClass()
    {
        DatabaseDescriptor.setPermissionsValidity(DatabaseDescriptor.getRawConfig().permissions_validity_in_ms);
    }

    @Test
    public void testSelectAllWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.credentials_cache");

        assertEmpty(result);
    }

    @Test
    public void testSelectAllWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        UntypedResultSet result = execute("SELECT * FROM vts.credentials_cache");

        assertRows(result,
                row("role_a", hashedPasswordRoleA),
                row("role_b", hashedPasswordRoleB));
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.credentials_cache WHERE role='role_a'");

        assertEmpty(result);
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        UntypedResultSet result = execute("SELECT * FROM vts.credentials_cache WHERE role='role_a'");

        assertRows(result, row("role_a", hashedPasswordRoleA));
    }

    @Test
    public void testDeletePartition() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        execute("DELETE FROM vts.credentials_cache WHERE role='role_a'");
        UntypedResultSet result = execute("SELECT * FROM vts.credentials_cache");

        assertRows(result, row("role_b", hashedPasswordRoleB));
    }

    @Test
    public void testTruncateTable() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        execute("TRUNCATE vts.credentials_cache");
        UntypedResultSet result = execute("SELECT * FROM vts.credentials_cache");

        assertEmpty(result);
    }

    @Test
    public void testUnsupportedOperations() throws Throwable
    {
        // range tombstone is not supported, however, this table has no clustering columns, so it is not covered by tests

        // column deletion is not supported
        assertInvalidMessage("Column deletion is not supported by table vts.credentials_cache",
                "DELETE salted_hash FROM vts.credentials_cache WHERE role='role_e'");

        // insert is not supported
        assertInvalidMessage("Column modification is not supported by table vts.credentials_cache",
                "INSERT INTO vts.credentials_cache (role) VALUES ('role_e')");
        assertInvalidMessage("Column modification is not supported by table vts.credentials_cache",
                "INSERT INTO vts.credentials_cache (role, salted_hash) VALUES ('role_e', 'ignored')");

        // update is not supported
        assertInvalidMessage("Column modification is not supported by table vts.credentials_cache",
                "UPDATE vts.credentials_cache SET salted_hash='ignored' WHERE role='role_e'");
    }

    @Test
    public void testDeleteRowWithInvalidValues() throws Throwable
    {
        cachePermissions(ROLE_A);

        execute("DELETE FROM vts.credentials_cache WHERE role='invalid_role'");
        UntypedResultSet result = execute("SELECT * FROM vts.credentials_cache WHERE role='role_a'");

        assertRows(result, row("role_a", hashedPasswordRoleA));
    }

    private void cachePermissions(RoleResource roleResource)
    {
        IAuthenticator.SaslNegotiator saslNegotiator = passwordAuthenticator.newSaslNegotiator(null);
        saslNegotiator.evaluateResponse(new PlainTextAuthProvider(roleResource.getRoleName(), "ignored")
                .newAuthenticator((EndPoint) null, null)
                .initialResponse());
        saslNegotiator.getAuthenticatedUser();
    }
}
