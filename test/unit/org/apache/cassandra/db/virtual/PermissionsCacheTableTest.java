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

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.cassandra.SchemaLoader;
import org.apache.cassandra.auth.AuthTestUtils;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.CQLTester;
import org.apache.cassandra.cql3.UntypedResultSet;

import static org.apache.cassandra.auth.AuthTestUtils.ROLE_A;
import static org.apache.cassandra.auth.AuthTestUtils.ROLE_B;

public class PermissionsCacheTableTest extends CQLTester
{
    private static final String KS_NAME = "vts";

    private PermissionsCacheTable table;

    @BeforeClass
    public static void setUpClass()
    {
        // high value is used for convenient debugging
        DatabaseDescriptor.setPermissionsValidity(20_000);

        CQLTester.setUpClass();
        AuthTestUtils.LocalCassandraRoleManager roleManager = new AuthTestUtils.LocalCassandraRoleManager();
        AuthTestUtils.LocalCassandraAuthorizer authorizer = new AuthTestUtils.LocalCassandraAuthorizer();
        SchemaLoader.setupAuth(roleManager,
                new AuthTestUtils.LocalPasswordAuthenticator(),
                authorizer,
                new AuthTestUtils.LocalCassandraNetworkAuthorizer());

        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_A, AuthTestUtils.getLoginRoleOprions());
        roleManager.createRole(AuthenticatedUser.SYSTEM_USER, ROLE_B, AuthTestUtils.getLoginRoleOprions());

        List<IResource> resources = Arrays.asList(
                DataResource.root(),
                DataResource.keyspace(KEYSPACE),
                DataResource.table(KEYSPACE, "t1"));

        for (IResource resource : resources)
        {
            Set<Permission> permissions = resource.applicablePermissions();
            authorizer.grant(AuthenticatedUser.SYSTEM_USER, permissions, resource, ROLE_A);
            authorizer.grant(AuthenticatedUser.SYSTEM_USER, permissions, resource, ROLE_B);
        }
    }

    @Before
    public void config()
    {
        table = new PermissionsCacheTable(KS_NAME);
        VirtualKeyspaceRegistry.instance.register(new VirtualKeyspace(KS_NAME, ImmutableList.of(table)));

        // ensure nothing keeps cached between tests
        AuthenticatedUser.permissionsCache.invalidate();
    }

    @AfterClass
    public static void tearDownClass()
    {
        DatabaseDescriptor.setPermissionsValidity(DatabaseDescriptor.getRawConfig().permissions_validity_in_ms);
    }

    @Test
    public void testSelectAllWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache");

        assertEmpty(result);
    }

    @Test
    public void testSelectAllWhenPermissionsAreCached() throws Throwable
    {
        cachePermissionsForResource(ROLE_A, DataResource.root());
        cachePermissionsForResource(ROLE_A, DataResource.keyspace(KEYSPACE));
        cachePermissionsForResource(ROLE_B, DataResource.table(KEYSPACE, "t1"));

        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache");

        assertRows(result,
                row("role_a", "data", "ALTER"),
                row("role_a", "data", "AUTHORIZE"),
                row("role_a", "data", "CREATE"),
                row("role_a", "data", "DROP"),
                row("role_a", "data", "MODIFY"),
                row("role_a", "data", "SELECT"),
                row("role_a", "data/cql_test_keyspace", "ALTER"),
                row("role_a", "data/cql_test_keyspace", "AUTHORIZE"),
                row("role_a", "data/cql_test_keyspace", "CREATE"),
                row("role_a", "data/cql_test_keyspace", "DROP"),
                row("role_a", "data/cql_test_keyspace", "MODIFY"),
                row("role_a", "data/cql_test_keyspace", "SELECT"),
                row("role_b", "data/cql_test_keyspace/t1", "ALTER"),
                row("role_b", "data/cql_test_keyspace/t1", "AUTHORIZE"),
                row("role_b", "data/cql_test_keyspace/t1", "DROP"),
                row("role_b", "data/cql_test_keyspace/t1", "MODIFY"),
                row("role_b", "data/cql_test_keyspace/t1", "SELECT"));
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache WHERE role='role_a' AND resource='data'");

        assertEmpty(result);
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreCached() throws Throwable
    {
        cachePermissionsForResource(ROLE_A, DataResource.root());
        cachePermissionsForResource(ROLE_A, DataResource.keyspace(KEYSPACE));
        cachePermissionsForResource(ROLE_B, DataResource.table(KEYSPACE, "t1"));

        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache WHERE role='role_a' AND resource='data'");

        assertRows(result,
                row("role_a", "data", "ALTER"),
                row("role_a", "data", "AUTHORIZE"),
                row("role_a", "data", "CREATE"),
                row("role_a", "data", "DROP"),
                row("role_a", "data", "MODIFY"),
                row("role_a", "data", "SELECT"));
    }

    @Test
    public void testSelectRowWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache WHERE role='role_a' AND resource='data' AND permission='SELECT'");

        assertEmpty(result);
    }

    @Test
    public void testSelectRowWhenPermissionsAreCached() throws Throwable
    {
        cachePermissionsForResource(ROLE_A, DataResource.root());
        cachePermissionsForResource(ROLE_A, DataResource.keyspace(KEYSPACE));
        cachePermissionsForResource(ROLE_B, DataResource.table(KEYSPACE, "t1"));

        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache WHERE role='role_a' AND resource='data' AND permission='SELECT'");

        assertRows(result, row("role_a", "data", "SELECT"));
    }

    @Test
    public void testDeletePartition() throws Throwable
    {
        cachePermissionsForResource(ROLE_A, DataResource.root());
        cachePermissionsForResource(ROLE_A, DataResource.keyspace(KEYSPACE));

        execute("DELETE FROM vts.permissions_cache WHERE role='role_a' AND resource='data'");
        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache");

        assertRows(result,
                row("role_a", "data/cql_test_keyspace", "ALTER"),
                row("role_a", "data/cql_test_keyspace", "AUTHORIZE"),
                row("role_a", "data/cql_test_keyspace", "CREATE"),
                row("role_a", "data/cql_test_keyspace", "DROP"),
                row("role_a", "data/cql_test_keyspace", "MODIFY"),
                row("role_a", "data/cql_test_keyspace", "SELECT"));
    }

    @Test
    public void testDeleteRow() throws Throwable
    {
        cachePermissionsForResource(ROLE_A, DataResource.root());

        execute("DELETE FROM vts.permissions_cache WHERE role='role_a' AND resource='data' AND permission='SELECT'");
        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache WHERE role='role_a' AND resource='data'");

        assertRows(result,
                row("role_a", "data", "ALTER"),
                row("role_a", "data", "AUTHORIZE"),
                row("role_a", "data", "CREATE"),
                row("role_a", "data", "DROP"),
                row("role_a", "data", "MODIFY"));
    }

    @Test
    public void testTruncateTable() throws Throwable
    {
        cachePermissionsForResource(ROLE_A, DataResource.root());
        cachePermissionsForResource(ROLE_B, DataResource.table(KEYSPACE, "t1"));

        execute("TRUNCATE vts.permissions_cache");
        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache");

        assertEmpty(result);
    }

    @Test
    public void testUnsupportedOperations() throws Throwable
    {
        // range tombstone is not supported
        assertInvalidMessage("Range deletion is not supported by table vts.permissions_cache",
                "DELETE FROM vts.permissions_cache WHERE role='role_e' AND resource='data' AND permission>'SELECT'");

        // column deletion is not supported, however, this table has no regular columns, so it is not covered by tests

        // insert is not supported
        assertInvalidMessage("Column modification is not supported by table vts.permissions_cache",
                "INSERT INTO vts.permissions_cache (role, resource, permission) VALUES ('role_e', 'data', 'SELECT')");

        // update is not supported, however, this table has no regular columns, so it is not covered by tests
    }

    @Test
    public void testDeleteRowWithInvalidValues() throws Throwable
    {
        cachePermissionsForResource(ROLE_A, DataResource.root());

        execute("DELETE FROM vts.permissions_cache WHERE role='invalid_role' AND resource='data' AND permission='SELECT'");
        execute("DELETE FROM vts.permissions_cache WHERE role='role_a' AND resource='invalid_resource' AND permission='SELECT'");
        execute("DELETE FROM vts.permissions_cache WHERE role='role_a' AND resource='data' AND permission='invalid_permissions'");
        UntypedResultSet result = execute("SELECT * FROM vts.permissions_cache WHERE role='role_a' AND resource='data'");

        assertRows(result,
                row("role_a", "data", "ALTER"),
                row("role_a", "data", "AUTHORIZE"),
                row("role_a", "data", "CREATE"),
                row("role_a", "data", "DROP"),
                row("role_a", "data", "MODIFY"),
                row("role_a", "data", "SELECT"));
    }

    private void cachePermissionsForResource(RoleResource roleResource, IResource resource)
    {
        AuthenticatedUser role = new AuthenticatedUser(roleResource.getRoleName());
        role.getPermissions(resource);
    }
}
