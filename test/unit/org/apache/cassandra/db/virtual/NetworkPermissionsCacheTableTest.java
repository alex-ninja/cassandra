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

import org.apache.cassandra.SchemaLoader;
import org.apache.cassandra.auth.AuthTestUtils;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.DCPermissions;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.CQLTester;
import org.apache.cassandra.cql3.UntypedResultSet;

import static org.apache.cassandra.auth.AuthTestUtils.ROLE_A;
import static org.apache.cassandra.auth.AuthTestUtils.ROLE_B;

public class NetworkPermissionsCacheTableTest extends CQLTester
{
    private static final String KS_NAME = "vts";

    private NetworkPermissionsCacheTable table;

    @BeforeClass
    public static void setUpClass()
    {
        // high value is used for convenient debugging
        DatabaseDescriptor.setPermissionsValidity(20_000);

        CQLTester.setUpClass();
        AuthTestUtils.LocalCassandraRoleManager roleManager = new AuthTestUtils.LocalCassandraRoleManager();
        AuthTestUtils.LocalCassandraNetworkAuthorizer networkAuthorizer = new AuthTestUtils.LocalCassandraNetworkAuthorizer();
        SchemaLoader.setupAuth(roleManager,
                new AuthTestUtils.LocalPasswordAuthenticator(),
                new AuthTestUtils.LocalCassandraAuthorizer(),
                networkAuthorizer);

        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_A, AuthTestUtils.getLoginRoleOprions());
        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_B, AuthTestUtils.getLoginRoleOprions());

        networkAuthorizer.setRoleDatacenters(ROLE_A, DCPermissions.all());
        networkAuthorizer.setRoleDatacenters(ROLE_B, DCPermissions.subset(DATA_CENTER, DATA_CENTER_REMOTE));
    }

    @Before
    public void config()
    {
        table = new NetworkPermissionsCacheTable(KS_NAME);
        VirtualKeyspaceRegistry.instance.register(new VirtualKeyspace(KS_NAME, ImmutableList.of(table)));

        // ensure nothing keeps cached between tests
        AuthenticatedUser.networkPermissionsCache.invalidate();
    }

    @AfterClass
    public static void tearDownClass()
    {
        DatabaseDescriptor.setPermissionsValidity(DatabaseDescriptor.getRawConfig().permissions_validity_in_ms);
    }

    @Test
    public void testSelectAllWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.network_permissions_cache");

        assertEmpty(result);
    }

    @Test
    public void testSelectAllWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        UntypedResultSet result = execute("SELECT * FROM vts.network_permissions_cache");

        assertRows(result,
                row("role_a", "ALL"),
                row("role_b", "datacenter1, datacenter2"));
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.network_permissions_cache WHERE role='role_a'");

        assertEmpty(result);
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        UntypedResultSet result = execute("SELECT * FROM vts.network_permissions_cache WHERE role='role_a'");

        assertRows(result, row("role_a", "ALL"));
    }

    @Test
    public void testDeletePartition() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        execute("DELETE FROM vts.network_permissions_cache WHERE role='role_a'");
        UntypedResultSet result = execute("SELECT * FROM vts.network_permissions_cache");

        assertRows(result, row("role_b", "datacenter1, datacenter2"));
    }

    @Test
    public void testTruncateTable() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        execute("TRUNCATE vts.network_permissions_cache");
        UntypedResultSet result = execute("SELECT * FROM vts.network_permissions_cache");

        assertEmpty(result);
    }

    @Test
    public void testUnsupportedOperations() throws Throwable
    {
        // range tombstone is not supported, however, this table has no clustering columns, so it is not covered by tests

        // column deletion is not supported
        assertInvalidMessage("Column deletion is not supported by table vts.network_permissions_cache",
                "DELETE allowed_dcs FROM vts.network_permissions_cache WHERE role='role_e'");

        // insert is not supported
        assertInvalidMessage("Column modification is not supported by table vts.network_permissions_cache",
                "INSERT INTO vts.network_permissions_cache (role) VALUES ('role_e')");
        assertInvalidMessage("Column modification is not supported by table vts.network_permissions_cache",
                "INSERT INTO vts.network_permissions_cache (role, allowed_dcs) VALUES ('role_e', 'ALL')");

        // update is not supported
        assertInvalidMessage("Column modification is not supported by table vts.network_permissions_cache",
                "UPDATE vts.network_permissions_cache SET allowed_dcs='ALL' WHERE role='role_e'");
    }

    @Test
    public void testDeleteRowWithInvalidValues() throws Throwable
    {
        cachePermissions(ROLE_A);

        execute("DELETE FROM vts.network_permissions_cache WHERE role='invalid_role'");
        UntypedResultSet result = execute("SELECT * FROM vts.network_permissions_cache WHERE role='role_a'");

        assertRows(result, row("role_a", "ALL"));
    }

    private void cachePermissions(RoleResource roleResource)
    {
        AuthenticatedUser.networkPermissionsCache.get(roleResource);
    }
}
