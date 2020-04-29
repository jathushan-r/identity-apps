/**
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import { AlertLevels } from "@wso2is/core/models";
import { addAlert } from "@wso2is/core/store";
import { Heading, Hint } from "@wso2is/react-components";
import _ from "lodash";
import React, { FunctionComponent, useEffect, useState } from "react";
import { useDispatch } from "react-redux";
import { Button, Divider, DropdownItemProps, Form, Grid, Icon, Label, Popup } from "semantic-ui-react";
import { getRolesList } from "../../../../api";
import { RoleListInterface, RolesInterface } from "../../../../models";


interface OutboundProvisioningRolesPropsInterface {
    initialRoles: string[];
    triggerSubmit: boolean;
    onSubmit: (selectedRoles: string[]) => void;
}

export const OutboundProvisioningRoles: FunctionComponent<OutboundProvisioningRolesPropsInterface> = (
    props: OutboundProvisioningRolesPropsInterface) => {

    const {
        initialRoles,
        onSubmit,
        triggerSubmit
    } = props;

    const [selectedRole, setSelectedRole] = useState<string>(undefined);
    const [selectedRoles, setSelectedRoles] = useState<string[]>(undefined);
    const [roleList, setRoleList] = useState<RolesInterface[]>(undefined);

    const dispatch = useDispatch();

    const handleRoleAdd = (event) => {
        event.preventDefault();
        if (_.isEmpty(selectedRole)) {
            return;
        }
        if (_.isEmpty(selectedRoles.find(role => role === selectedRole))) {
            setSelectedRoles([...selectedRoles, selectedRole]);
        }
        setSelectedRole("");
    };

    const handleRoleRemove = (removingRole: string) => {
        if (_.isEmpty(removingRole)) {
            return;
        }
        setSelectedRoles(_.filter(selectedRoles, role => !_.isEqual(removingRole, role)));
    };

    useEffect(() => {
        getRolesList(null)
            .then((response) => {
                if (response.status === 200) {
                    const allRole: RoleListInterface = response.data;
                    setRoleList(allRole?.Resources?.filter((role) => {
                        return !(role.displayName
                            .includes("Application/") || role.displayName.includes("Internal/"))
                    }));
                }
            })
            .catch((error) => {
                dispatch(addAlert({
                    description: error?.description ? error.description : "An error occurred while retrieving roles.",
                    level: AlertLevels.ERROR,
                    message: "Get Error"
                }));
            });
        setSelectedRoles(initialRoles === undefined ? [] : initialRoles);
    }, []);

    useEffect(() => {
        if (selectedRoles === undefined) {
            return;
        }
        onSubmit(selectedRoles);
    }, [triggerSubmit]);

    return (
        <Grid>
            <Grid.Row columns={ 1 }>
                <Grid.Column mobile={ 16 } tablet={ 16 } computer={ 8 }>
                    <Divider/>
                    <Divider hidden/>
                    <Heading as="h5">OutBound Provisioning Roles</Heading>
                </Grid.Column>
            </Grid.Row>

            <Grid.Row columns={ 2 }>
                <Grid.Column mobile={ 16 } tablet={ 16 } computer={ 8 }>
                    <Form className="outbound-provisioning-roles role-select-dropdown">
                        <Form.Select
                            options={ roleList?.map((role) => {
                                return {
                                    key: role.id,
                                    text: role.displayName,
                                    value: role.displayName
                                } as DropdownItemProps
                            }) }
                            value={ selectedRole }
                            placeholder={ "Select Role" }
                            onChange={
                                (event, data) => {
                                    if (_.isEmpty(data?.value?.toString())) {
                                        return;
                                    }
                                    setSelectedRole(data.value.toString())
                                }
                            }
                            search
                            label={ "Role" }
                        />
                        <Popup
                            trigger={
                                (
                                    <Button
                                        onClick={ (e) => handleRoleAdd(e) }
                                        icon="add"
                                        type="button"
                                        disabled={ false }
                                        className="inline"
                                    />
                                )
                            }
                            position="top center"
                            content="Add Role"
                            inverted
                        />
                    </Form>

                    <Hint>
                        Select and add as identity provider outbound provisioning roles
                    </Hint>

                    {
                        selectedRoles && selectedRoles?.map((selectedRole, index) => {
                            return (
                                <Label
                                    key={ index }
                                >
                                    {selectedRole}
                                    <Icon
                                        name="delete"
                                        onClick={ () => handleRoleRemove(selectedRole) }
                                    />
                                </Label>
                            );
                        })
                    }
                </Grid.Column>
            </Grid.Row>
        </Grid>
    );
};
