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
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.auth.Roles;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.CQLTester;
import org.apache.cassandra.cql3.UntypedResultSet;

import static org.apache.cassandra.auth.AuthTestUtils.ROLE_A;
import static org.apache.cassandra.auth.AuthTestUtils.ROLE_B;
import static org.apache.cassandra.auth.AuthTestUtils.ROLE_C;

public class RolesCacheTableTest extends CQLTester
{
    private static final String KS_NAME = "vts";

    private RolesCacheTable table;

    @BeforeClass
    public static void setUpClass()
    {
        // high value is used for convenient debugging
        DatabaseDescriptor.setPermissionsValidity(20_000);

        CQLTester.setUpClass();
        AuthTestUtils.LocalCassandraRoleManager roleManager = new AuthTestUtils.LocalCassandraRoleManager();
        SchemaLoader.setupAuth(roleManager,
                new AuthTestUtils.LocalPasswordAuthenticator(),
                new AuthTestUtils.LocalCassandraAuthorizer(),
                new AuthTestUtils.LocalCassandraNetworkAuthorizer());

        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_A, AuthTestUtils.getLoginRoleOprions());
        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_B, AuthTestUtils.getLoginRoleOprions());
        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_C, AuthTestUtils.getLoginRoleOprions());

        AuthTestUtils.grantRolesTo(roleManager, ROLE_A, ROLE_C);
        AuthTestUtils.grantRolesTo(roleManager, ROLE_B, ROLE_C);
    }

    @Before
    public void config()
    {
        table = new RolesCacheTable(KS_NAME);
        VirtualKeyspaceRegistry.instance.register(new VirtualKeyspace(KS_NAME, ImmutableList.of(table)));

        // ensure nothing keeps cached between tests
        Roles.cache.invalidate();
    }

    @AfterClass
    public static void tearDownClass()
    {
        DatabaseDescriptor.setPermissionsValidity(DatabaseDescriptor.getRawConfig().permissions_validity_in_ms);
    }

    @Test
    public void testSelectAllWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache");

        assertEmpty(result);
    }

    @Test
    public void testSelectAllWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache");

        assertRows(result,
                row("role_a", "roles/role_a"),
                row("role_a", "roles/role_c"),
                row("role_b", "roles/role_b"),
                row("role_b", "roles/role_c"));
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache WHERE role='role_a'");

        assertEmpty(result);
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache WHERE role='role_a'");

        assertRows(result,
                row("role_a", "roles/role_a"),
                row("role_a", "roles/role_c"));
    }

    @Test
    public void testSelectRowWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache WHERE role='role_a' AND resource='roles/role_a'");

        assertEmpty(result);
    }

    @Test
    public void testSelectRowWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);

        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache WHERE role='role_a' AND resource='roles/role_a'");

        assertRows(result, row("role_a", "roles/role_a"));
    }

    @Test
    public void testDeletePartition() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        execute("DELETE FROM vts.roles_cache WHERE role='role_a'");
        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache");

        assertRows(result,
                row("role_b", "roles/role_b"),
                row("role_b", "roles/role_c"));
    }

    @Test
    public void testDeleteRow() throws Throwable
    {
        cachePermissions(ROLE_A);

        execute("DELETE FROM vts.roles_cache WHERE role='role_a' AND resource='roles/role_a'");
        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache WHERE role='role_a'");

        assertRows(result, row("role_a", "roles/role_c"));
    }

    @Test
    public void testTruncateTable() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        execute("TRUNCATE vts.roles_cache");
        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache");

        assertEmpty(result);
    }

    @Test
    public void testUnsupportedOperations() throws Throwable
    {
        // range tombstone is not supported
        assertInvalidMessage("Range deletion is not supported by table vts.roles_cache",
                "DELETE FROM vts.roles_cache WHERE role='role_e' AND resource>'roles/role_e'");

        // column deletion is not supported, however, this table has no regular columns, so it is not covered by tests

        // insert is not supported
        assertInvalidMessage("Column modification is not supported by table vts.roles_cache",
                "INSERT INTO vts.roles_cache (role, resource) VALUES ('role_e', 'roles/role_e')");

        // update is not supported, however, this table has no regular columns, so it is not covered by tests
    }

    @Test
    public void testDeleteRowWithInvalidValues() throws Throwable
    {
        cachePermissions(ROLE_A);

        execute("DELETE FROM vts.roles_cache WHERE role='invalid_role' AND resource='roles/role_a'");
        execute("DELETE FROM vts.roles_cache WHERE role='role_a' AND resource='invalid_resource'");
        UntypedResultSet result = execute("SELECT * FROM vts.roles_cache WHERE role='role_a'");

        assertRows(result,
                row("role_a", "roles/role_a"),
                row("role_a", "roles/role_c"));
    }

    private void cachePermissions(RoleResource roleResource)
    {
        Roles.getRoleDetails(roleResource);
    }
}
