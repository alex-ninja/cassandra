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
import javax.security.auth.Subject;

import com.google.common.collect.ImmutableList;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.cassandra.SchemaLoader;
import org.apache.cassandra.auth.AuthTestUtils;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.CassandraPrincipal;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.JMXResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.auth.jmx.AuthorizationProxy;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.CQLTester;
import org.apache.cassandra.cql3.UntypedResultSet;

import static org.apache.cassandra.auth.AuthTestUtils.ROLE_A;
import static org.apache.cassandra.auth.AuthTestUtils.ROLE_B;

public class JmxPermissionsCacheTableTest extends CQLTester
{
    private static final String KS_NAME = "vts";
    private static final AuthorizationProxy authorizationProxy = new AuthTestUtils.NoAuthSetupAuthorizationProxy();

    private JmxPermissionsCacheTable table;

    // this method is intentionally not called "setUpClass" to let it throw exception brought by startJMXServer method 
    @BeforeClass
    public static void setup() throws Exception {
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
                JMXResource.root(),
                JMXResource.mbean("org.apache.cassandra.db:type=Tables,*"));

        for (IResource resource : resources)
        {
            Set<Permission> permissions = resource.applicablePermissions();
            authorizer.grant(AuthenticatedUser.SYSTEM_USER, permissions, resource, ROLE_A);
            authorizer.grant(AuthenticatedUser.SYSTEM_USER, permissions, resource, ROLE_B);
        }

        startJMXServer();
    }

    @Before
    public void config()
    {
        table = new JmxPermissionsCacheTable(KS_NAME);
        VirtualKeyspaceRegistry.instance.register(new VirtualKeyspace(KS_NAME, ImmutableList.of(table)));

        // ensure nothing keeps cached between tests
        AuthorizationProxy.jmxPermissionsCache.invalidate();
    }

    @AfterClass
    public static void tearDownClass()
    {
        DatabaseDescriptor.setPermissionsValidity(DatabaseDescriptor.getRawConfig().permissions_validity_in_ms);
    }

    @Test
    public void testSelectAllWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache");

        assertEmpty(result);
    }

    @Test
    public void testSelectAllWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache");

        assertRows(result,
                row("role_a", "role_a", "mbean", "AUTHORIZE"),
                row("role_a", "role_a", "mbean", "DESCRIBE"),
                row("role_a", "role_a", "mbean", "EXECUTE"),
                row("role_a", "role_a", "mbean", "MODIFY"),
                row("role_a", "role_a", "mbean", "SELECT"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "AUTHORIZE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "DESCRIBE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "EXECUTE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "MODIFY"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "SELECT"),
                row("role_b", "role_b", "mbean", "AUTHORIZE"),
                row("role_b", "role_b", "mbean", "DESCRIBE"),
                row("role_b", "role_b", "mbean", "EXECUTE"),
                row("role_b", "role_b", "mbean", "MODIFY"),
                row("role_b", "role_b", "mbean", "SELECT"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "AUTHORIZE"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "DESCRIBE"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "EXECUTE"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "MODIFY"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "SELECT"));
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache WHERE role='role_a'");

        assertEmpty(result);
    }

    @Test
    public void testSelectPartitionWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache WHERE role='role_a'");

        assertRows(result,
                row("role_a", "role_a", "mbean", "AUTHORIZE"),
                row("role_a", "role_a", "mbean", "DESCRIBE"),
                row("role_a", "role_a", "mbean", "EXECUTE"),
                row("role_a", "role_a", "mbean", "MODIFY"),
                row("role_a", "role_a", "mbean", "SELECT"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "AUTHORIZE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "DESCRIBE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "EXECUTE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "MODIFY"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "SELECT"));
    }

    @Test
    public void testSelectRowWhenPermissionsAreNotCached() throws Throwable
    {
        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='role_a' AND resource='mbean' AND permission='SELECT'");

        assertEmpty(result);
    }

    @Test
    public void testSelectRowWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);

        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='role_a' AND resource='mbean' AND permission='SELECT'");

        assertRows(result, row("role_a", "role_a", "mbean", "SELECT"));
    }

    @Test
    public void testSelectRowsForPartialClusteringColumnsWhenPermissionsAreCached() throws Throwable
    {
        cachePermissions(ROLE_A);

        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='role_a'");

        assertRows(result,
                row("role_a", "role_a", "mbean", "AUTHORIZE"),
                row("role_a", "role_a", "mbean", "DESCRIBE"),
                row("role_a", "role_a", "mbean", "EXECUTE"),
                row("role_a", "role_a", "mbean", "MODIFY"),
                row("role_a", "role_a", "mbean", "SELECT"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "AUTHORIZE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "DESCRIBE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "EXECUTE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "MODIFY"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "SELECT"));

        result = execute("SELECT * FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='role_a' AND resource='mbean'");

        assertRows(result,
                row("role_a", "role_a", "mbean", "AUTHORIZE"),
                row("role_a", "role_a", "mbean", "DESCRIBE"),
                row("role_a", "role_a", "mbean", "EXECUTE"),
                row("role_a", "role_a", "mbean", "MODIFY"),
                row("role_a", "role_a", "mbean", "SELECT"));
    }

    @Test
    public void testDeletePartition() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        execute("DELETE FROM vts.jmx_permissions_cache WHERE role='role_a'");
        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache");

        assertRows(result,
                row("role_b", "role_b", "mbean", "AUTHORIZE"),
                row("role_b", "role_b", "mbean", "DESCRIBE"),
                row("role_b", "role_b", "mbean", "EXECUTE"),
                row("role_b", "role_b", "mbean", "MODIFY"),
                row("role_b", "role_b", "mbean", "SELECT"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "AUTHORIZE"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "DESCRIBE"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "EXECUTE"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "MODIFY"),
                row("role_b", "role_b", "mbean/org.apache.cassandra.db:type=Tables,*", "SELECT"));
    }

    @Test
    public void testDeleteRow() throws Throwable
    {
        cachePermissions(ROLE_A);

        execute("DELETE FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='role_a' AND resource='mbean' AND permission='SELECT'");
        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='role_a' AND resource='mbean'");

        assertRows(result,
                row("role_a", "role_a", "mbean", "AUTHORIZE"),
                row("role_a", "role_a", "mbean", "DESCRIBE"),
                row("role_a", "role_a", "mbean", "EXECUTE"),
                row("role_a", "role_a", "mbean", "MODIFY"));
    }

    @Test
    public void testTruncateTable() throws Throwable
    {
        cachePermissions(ROLE_A);
        cachePermissions(ROLE_B);

        execute("TRUNCATE vts.jmx_permissions_cache");
        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache");

        assertEmpty(result);
    }

    @Test
    public void testUnsupportedOperations() throws Throwable
    {
        // range tombstone is not supported
        assertInvalidMessage("Range deletion is not supported by table vts.jmx_permissions_cache",
                "DELETE FROM vts.jmx_permissions_cache WHERE role='role_e' AND grantee='role_e' AND resource='mbean' AND permission>'SELECT'");
        assertInvalidMessage("Range deletion is not supported by table vts.jmx_permissions_cache",
                "DELETE FROM vts.jmx_permissions_cache WHERE role='role_e' AND grantee='role_e' AND resource='mbean'");
        assertInvalidMessage("Range deletion is not supported by table vts.jmx_permissions_cache",
                "DELETE FROM vts.jmx_permissions_cache WHERE role='role_e' AND grantee='role_e'");

        // column deletion is not supported, however, this table has no regular columns, so it is not covered by tests

        // insert is not supported
        assertInvalidMessage("Column modification is not supported by table vts.jmx_permissions_cache",
                "INSERT INTO vts.jmx_permissions_cache (role, grantee, resource, permission) VALUES ('role_e', 'role_e', 'mbean', 'SELECT')");

        // update is not supported, however, this table has no regular columns, so it is not covered by tests
    }

    @Test
    public void testDeleteRowWithInvalidValues() throws Throwable
    {
        cachePermissions(ROLE_A);

        execute("DELETE FROM vts.jmx_permissions_cache WHERE role='invalid_role' AND grantee='role_a' AND resource='mbean' AND permission='SELECT'");
        execute("DELETE FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='invalid_role' AND resource='mbean' AND permission='SELECT'");
        execute("DELETE FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='role_a' AND resource='invalid_resource' AND permission='SELECT'");
        execute("DELETE FROM vts.jmx_permissions_cache WHERE role='role_a' AND grantee='role_a' AND resource='mbean' AND permission='invalid_permissions'");
        UntypedResultSet result = execute("SELECT * FROM vts.jmx_permissions_cache WHERE role='role_a'");

        assertRows(result,
                row("role_a", "role_a", "mbean", "AUTHORIZE"),
                row("role_a", "role_a", "mbean", "DESCRIBE"),
                row("role_a", "role_a", "mbean", "EXECUTE"),
                row("role_a", "role_a", "mbean", "MODIFY"),
                row("role_a", "role_a", "mbean", "SELECT"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "AUTHORIZE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "DESCRIBE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "EXECUTE"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "MODIFY"),
                row("role_a", "role_a", "mbean/org.apache.cassandra.db:type=Tables,*", "SELECT"));
    }

    private void cachePermissions(RoleResource roleResource)
    {
        Subject userSubject = new Subject();
        userSubject.getPrincipals().add(new CassandraPrincipal(roleResource.getRoleName()));

        authorizationProxy.authorize(userSubject, "queryNames", null);
    }
}
