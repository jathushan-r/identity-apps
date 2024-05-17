/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import { TestableComponentInterface } from "@wso2is/core/models";
import { Field, FormValue, Forms, Validation } from "@wso2is/forms";
import { AxiosResponse } from "axios";
import React, { FunctionComponent, ReactElement, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { DropdownItemProps, Grid, GridColumn, GridRow } from "semantic-ui-react";
import { SharedUserStoreConstants } from "@wso2is/admin.core.v1/constants";
import { SharedUserStoreUtils } from "@wso2is/admin.core.v1/utils";
import { getUserStoreList } from "@wso2is/admin.userstores.v1/api";
import { UserStoreListItem } from "@wso2is/admin.userstores.v1/models/user-stores";
import { searchRoleList } from "../../api/roles";
import {
    PRIMARY_DOMAIN
} from "../../constants/role-constants";
import { CreateRoleFormData, SearchRoleInterface } from "../../models/roles";

/**
 * Interface to capture role basics props.
 */
interface RoleBasicProps extends TestableComponentInterface {
    dummyProp?: string;
    triggerSubmit: boolean;
    initialValues: any;
    isAddGroup: boolean;
    onSubmit: (values: any) => void;
}

/**
 * Component to capture basic details of a new role.
 *
 * @param props - Role Basic prop types
 */
export const RoleBasics: FunctionComponent<RoleBasicProps> = (props: RoleBasicProps): ReactElement => {

    const {
        onSubmit,
        triggerSubmit,
        initialValues,
        isAddGroup,
        [ "data-testid" ]: testId
    } = props;

    const { t } = useTranslation();

    const [ isRoleNamePatternValid, setIsRoleNamePatternValid ] = useState<boolean>(true);
    const [ , setUserStoresList ] = useState([]);
    const [ userStore ] = useState<string>(SharedUserStoreConstants.PRIMARY_USER_STORE);
    const [ isRegExLoading, setRegExLoading ] = useState<boolean>(false);

    useEffect(() => {
        getUserStores();
    }, [ isAddGroup ]);

    /**
     * The following function validates role name against the user store regEx.
     *
     * @param roleName - User input role name
     */
    const validateRoleNamePattern = async (roleName: string): Promise<void> => {
        let userStoreRegEx: string = "";

        if (userStore !== PRIMARY_DOMAIN) {
            await SharedUserStoreUtils.getUserStoreRegEx(
                userStore,
                SharedUserStoreConstants.USERSTORE_REGEX_PROPERTIES.RolenameRegEx
            )
                .then((response: string) => {
                    setRegExLoading(true);
                    userStoreRegEx = response;
                });
        } else {
            userStoreRegEx = SharedUserStoreConstants.PRIMARY_USERSTORE_PROPERTY_VALUES.RolenameJavaScriptRegEx;
        }
        setIsRoleNamePatternValid(SharedUserStoreUtils.validateInputAgainstRegEx(roleName, userStoreRegEx));
    };

    /**
     * The following function fetch the user store list and set it to the state.
     */
    const getUserStores = () => {
        const storeOptions: DropdownItemProps[] = [
            {
                key: -1,
                text: "Primary",
                value: "primary"
            }
        ];
        let storeOption: DropdownItemProps = {
            key: null,
            text: "",
            value: ""
        };

        getUserStoreList()
            .then((response: AxiosResponse<UserStoreListItem[]>) => {
                if (storeOptions.length === 0) {
                    storeOptions.push(storeOption);
                }
                response.data.map((store: UserStoreListItem, index: number) => {
                    storeOption = {
                        key: index,
                        text: store.name,
                        value: store.name
                    };
                    storeOptions.push(storeOption);
                }
                );
                setUserStoresList(storeOptions);
            });

        setUserStoresList(storeOptions);
    };

    /**
     * Util method to collect form data for processing.
     *
     * @param values - contains values from form elements
     */
    const getFormValues = (values: any): CreateRoleFormData => {
        return {
            roleName: values.get("rolename").toString()
        };
    };

    return (
        <Forms
            data-testid={ testId }
            onSubmit={ (values: Map<string, FormValue>) => {
                onSubmit(getFormValues(values));
            } }
            submitState={ triggerSubmit }
        >
            <Grid>
                <GridRow>
                    <GridColumn mobile={ 16 } tablet={ 16 } computer={ 8 }>
                        <Field
                            data-testid={ `${ testId }-role-name-input` }
                            type="text"
                            name="rolename"
                            label={
                                t("roles:addRoleWizard.forms.roleBasicDetails." +
                                        "roleName.label",{ type: "Role" })
                            }
                            placeholder={
                                t("roles:addRoleWizard.forms.roleBasicDetails.roleName." +
                                        "placeholder", { type: "Role" })
                            }
                            required={ true }
                            requiredErrorMessage={
                                t("roles:addRoleWizard.forms.roleBasicDetails.roleName." +
                                        "validations.empty", { type: "Role" })
                            }
                            validation={ async (value: string, validation: Validation) => {

                                const searchData: SearchRoleInterface = {
                                    filter: "displayName eq " + value.toString(),
                                    schemas: [
                                        "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
                                    ],
                                    startIndex: 1
                                };
                                const response: AxiosResponse = await searchRoleList(searchData);

                                if (response?.data?.totalResults > 0) {
                                    validation.isValid = false;
                                    validation.errorMessages.push(
                                        t("roles:addRoleWizard.forms.roleBasicDetails." +
                                            "roleName.validations.duplicate", { type: "Role" })
                                    );
                                }

                                await validateRoleNamePattern(value.toString());

                                if (!isRoleNamePatternValid) {
                                    validation.isValid = false;
                                    validation.errorMessages.push(
                                        t("roles:addRoleWizard.forms.roleBasicDetails." +
                                                "roleName.validations.invalid", { type: "role" })
                                    );
                                }
                            } }
                            value={ initialValues && initialValues.roleName }
                            loading={ isRegExLoading }
                        />
                    </GridColumn>
                </GridRow>
            </Grid>
        </Forms>
    );
};
