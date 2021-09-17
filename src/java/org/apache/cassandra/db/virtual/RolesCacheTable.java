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

import org.apache.cassandra.auth.Role;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.auth.Roles;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.dht.LocalPartitioner;
import org.apache.cassandra.schema.TableMetadata;

final class RolesCacheTable extends AbstractMutableVirtualTable
{
    private static final String ROLE = "role";
    private static final String RESOURCE = "resource";

    RolesCacheTable(String keyspace)
    {
        super(TableMetadata.builder(keyspace, "roles_cache")
                .comment("Roles cache")
                .kind(TableMetadata.Kind.VIRTUAL)
                .partitioner(new LocalPartitioner(UTF8Type.instance))
                .addPartitionKeyColumn(ROLE, UTF8Type.instance)
                .addClusteringColumn(RESOURCE, UTF8Type.instance)
                .build());
    }

    public DataSet data()
    {
        SimpleDataSet result = new SimpleDataSet(metadata());

        Roles.cache.getAll().forEach((roleResource, roles) ->
                roles.forEach(role ->
                        result.row(roleResource.getRoleName(), role.resource.getName())));

        return result;
    }

    @Override
    protected void applyPartitionDeletion(ColumnValues partitionKey)
    {
        RoleResource roleResource = parseRoleResource(partitionKey.value(0));
        if (roleResource == null)
            return;

        Roles.cache.invalidate(roleResource);
    }

    @Override
    protected void applyRowDeletion(ColumnValues partitionKey, ColumnValues clusteringColumns)
    {
        RoleResource roleResource = parseRoleResource(partitionKey.value(0));
        RoleResource granteeRoleResource = parseRoleResourceFromName(clusteringColumns.value(0));
        if (roleResource == null || granteeRoleResource == null)
            return;

        Set<Role> roles = Roles.cache.get(roleResource);
        roles.removeIf(role -> role.resource.equals(granteeRoleResource));
    }

    @Override
    public void truncate()
    {
        Roles.cache.invalidate();
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
    private RoleResource parseRoleResourceFromName(String roleName)
    {
        try
        {
            return RoleResource.fromName(roleName);
        }
        catch (IllegalArgumentException e)
        {
            return null;
        }
    }
}
