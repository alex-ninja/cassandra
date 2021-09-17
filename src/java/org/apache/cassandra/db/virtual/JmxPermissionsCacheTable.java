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

import java.util.Set;
import javax.annotation.Nullable;

import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.PermissionDetails;
import org.apache.cassandra.auth.Resources;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.auth.jmx.AuthorizationProxy;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.dht.LocalPartitioner;
import org.apache.cassandra.schema.TableMetadata;

final class JmxPermissionsCacheTable extends AbstractMutableVirtualTable
{
    private static final String ROLE = "role";
    private static final String GRANTEE = "grantee";
    private static final String RESOURCE = "resource";
    private static final String PERMISSION = "permission";

    JmxPermissionsCacheTable(String keyspace)
    {
        super(TableMetadata.builder(keyspace, "jmx_permissions_cache")
                .comment("JMX permissions cache")
                .kind(TableMetadata.Kind.VIRTUAL)
                .partitioner(new LocalPartitioner(UTF8Type.instance))
                .addPartitionKeyColumn(ROLE, UTF8Type.instance)
                .addClusteringColumn(GRANTEE, UTF8Type.instance)
                .addClusteringColumn(RESOURCE, UTF8Type.instance)
                .addClusteringColumn(PERMISSION, UTF8Type.instance)
                .build());
    }

    public DataSet data()
    {
        SimpleDataSet result = new SimpleDataSet(metadata());

        AuthorizationProxy.jmxPermissionsCache.getAll().forEach((roleResource, permissionDetails) ->
                permissionDetails.forEach(permissionDetail -> result.row(
                        roleResource.getRoleName(),
                        permissionDetail.grantee,
                        permissionDetail.resource.getName(),
                        permissionDetail.permission.name())));

        return result;
    }

    @Override
    protected void applyPartitionDeletion(ColumnValues partitionKey)
    {
        RoleResource roleResource = parseRoleResource(partitionKey.value(0));
        if (roleResource == null)
            return;

        AuthorizationProxy.jmxPermissionsCache.invalidate(roleResource);
    }

    @Override
    protected void applyRowDeletion(ColumnValues partitionKey, ColumnValues clusteringColumns)
    {
        RoleResource roleResource = parseRoleResource(partitionKey.value(0));
        String grantee = clusteringColumns.value(0);
        IResource resource = parseResource(clusteringColumns.value(1));
        Permission permission = parsePermission(clusteringColumns.value(2));
        if (roleResource == null || resource == null || permission == null)
            return;

        Set<PermissionDetails> permissionDetails = AuthorizationProxy.jmxPermissionsCache.get(roleResource);
        permissionDetails.remove(new PermissionDetails(grantee, resource, permission));
    }

    @Override
    public void truncate()
    {
        AuthorizationProxy.jmxPermissionsCache.invalidate();
    }

    @Nullable
    private RoleResource parseRoleResource(String roleName)
    {
        try
        {
            return RoleResource.role(roleName);
        }
        catch (IllegalArgumentException e)
        {
            return null;
        }
    }

    @Nullable
    private IResource parseResource(String resourceName)
    {
        try
        {
            return Resources.fromName(resourceName);
        }
        catch (IllegalArgumentException e)
        {
            return null;
        }
    }

    @Nullable
    private Permission parsePermission(String permissionName)
    {
        try
        {
            return Permission.valueOf(permissionName);
        }
        catch (IllegalArgumentException e)
        {
            return null;
        }
    }
}
