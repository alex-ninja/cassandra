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

import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.Resources;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.dht.LocalPartitioner;
import org.apache.cassandra.schema.TableMetadata;
import org.apache.cassandra.utils.Pair;

final class PermissionsCacheTable extends AbstractMutableVirtualTable
{
    private static final String ROLE = "role";
    private static final String RESOURCE = "resource";
    private static final String PERMISSION = "permission";

    PermissionsCacheTable(String keyspace)
    {
        super(TableMetadata.builder(keyspace, "permissions_cache")
                .comment("Permissions cache")
                .kind(TableMetadata.Kind.VIRTUAL)
                .partitioner(new LocalPartitioner(UTF8Type.instance))
                .addPartitionKeyColumn(ROLE, UTF8Type.instance)
                .addPartitionKeyColumn(RESOURCE, UTF8Type.instance)
                .addClusteringColumn(PERMISSION, UTF8Type.instance)
                .build());
    }

    public DataSet data()
    {
        SimpleDataSet result = new SimpleDataSet(metadata());

        AuthenticatedUser.permissionsCache.getAll().forEach((userResoursePair, permissions) ->
                permissions.forEach(permission ->
                        result.row(userResoursePair.left.getName(), userResoursePair.right.getName(), permission.name())));

        return result;
    }

    @Override
    protected void applyPartitionDeletion(ColumnValues partitionKey)
    {
        AuthenticatedUser user = new AuthenticatedUser(partitionKey.value(0));
        IResource resource = parseResource(partitionKey.value(1));
        if (resource == null)
            return;

        AuthenticatedUser.permissionsCache.invalidate(Pair.create(user, resource));
    }

    @Override
    protected void applyRowDeletion(ColumnValues partitionKey, ColumnValues clusteringColumns)
    {
        AuthenticatedUser user = new AuthenticatedUser(partitionKey.value(0));
        IResource resource = parseResource(partitionKey.value(1));
        Permission permission = parsePermission(clusteringColumns.value(0));
        if (resource == null || permission == null)
            return;

        Set<Permission> permissions = AuthenticatedUser.permissionsCache.getPermissions(user, resource);
        permissions.remove(permission);
    }

    @Override
    public void truncate()
    {
        AuthenticatedUser.permissionsCache.invalidate();
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
