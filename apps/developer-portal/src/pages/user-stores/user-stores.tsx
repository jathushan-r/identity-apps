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

import { hasRequiredScopes } from "@wso2is/core/helpers";
import { TestableComponentInterface } from "@wso2is/core/models";
import { addAlert } from "@wso2is/core/store";
import { useTrigger } from "@wso2is/forms";
import { ListLayout, PageLayout, PrimaryButton } from "@wso2is/react-components";
import React, { FunctionComponent, ReactElement, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDispatch, useSelector } from "react-redux";
import { DropdownProps, Icon, PaginationProps } from "semantic-ui-react";
import { getUserStores } from "../../api";
import { AdvancedSearchWithBasicFilters, UserStoresList } from "../../components";
import { UIConstants, USERSTORE_TEMPLATES_PATH } from "../../constants";
import { history } from "../../helpers";
import { AlertLevels, FeatureConfigInterface, QueryParams, UserStoreListItem } from "../../models";
import { AppState } from "../../store";
import { filterList, sortList } from "../../utils";

/**
 * Props for the Userstore page.
 */
type UserStoresPageInterface = TestableComponentInterface;

/**
 * This renders the Userstores page.
 *
 * @param {UserStoresPageInterface} props - Props injected to the component.
 *
 * @return {React.ReactElement}
 */
export const UserStores: FunctionComponent<UserStoresPageInterface> = (
    props: UserStoresPageInterface
): ReactElement => {

    const {
        [ "data-testid" ]: testId
    } = props;

    const { t } = useTranslation();

    /**
     * Sets the attributes by which the list can be sorted.
     */
    const SORT_BY = [
        {
            key: 0,
            text: t("common:name"),
            value: "name"
        },
        {
            key: 1,
            text: t("common:description"),
            value: "description"
        }
    ];

    const featureConfig: FeatureConfigInterface = useSelector((state: AppState) => state.config.features);

    const [ userStores, setUserStores ] = useState<UserStoreListItem[]>([]);
    const [ offset, setOffset ] = useState(0);
    const [ listItemLimit, setListItemLimit ] = useState<number>(UIConstants.DEFAULT_RESOURCE_LIST_ITEM_LIMIT);
    const [ isLoading, setIsLoading ] = useState(true);
    const [ filteredUserStores, setFilteredUserStores ] = useState<UserStoreListItem[]>([]);
    const [ sortBy, setSortBy ] = useState(SORT_BY[ 0 ]);
    const [ sortOrder, setSortOrder ] = useState(true);
    const [ searchQuery, setSearchQuery ] = useState("");
    const [ triggerClearQuery, setTriggerClearQuery ] = useState<boolean>(false);

    const dispatch = useDispatch();

    const [ resetPagination, setResetPagination ] = useTrigger();

    /**
     * Fetches all userstores.
     *
     * @param {number} limit.
     * @param {string} sort.
     * @param {number} offset.
     * @param {string} filter.
     */
    const fetchUserStores = (limit?: number, sort?: string, offset?: number, filter?: string) => {
        const params: QueryParams = {
            filter: filter || null,
            limit: limit || null,
            offset: offset || null,
            sort: sort || null
        };
        setIsLoading(true);
        getUserStores(params).then(response => {
            setUserStores(response);
            setFilteredUserStores(response);
            setIsLoading(false);
        }).catch(error => {
            setIsLoading(false);
            dispatch(addAlert(
                {
                    description: error?.description
                        || t("devPortal:components.userstores.notifications.fetchUserstores.genericError.description"),
                    level: AlertLevels.ERROR,
                    message: error?.message
                        || t("devPortal:components.userstores.notifications.fetchUserstores.genericError.message")
                }
            ));
        });
    };

    useEffect(() => {
        fetchUserStores(null, null, null, null);
    }, []);

    useEffect(() => {
        setFilteredUserStores((sortList(filteredUserStores, sortBy.value, sortOrder)));
    }, [ sortBy, sortOrder ]);

    /**
     * This slices and returns a portion of the list.
     *
     * @param {number} list.
     * @param {number} limit.
     * @param {number} offset.
     *
     * @return {UserStoreListItem[]} Paginated list.
     */
    const paginate = (list: UserStoreListItem[], limit: number, offset: number): UserStoreListItem[] => {
        return list?.slice(offset, offset + limit);
    };

    /**
     * Handles the change in the number of items to display.
     *
     * @param {React.MouseEvent<HTMLAnchorElement>} event.
     * @param {DropdownProps} data.
     */
    const handleItemsPerPageDropdownChange = (event: React.MouseEvent<HTMLAnchorElement>, data: DropdownProps) => {
        setListItemLimit(data.value as number);
    };

    /**
     * This paginates.
     *
     * @param {React.MouseEvent<HTMLAnchorElement>} event.
     * @param {PaginationProps} data.
     */
    const handlePaginationChange = (event: React.MouseEvent<HTMLAnchorElement>, data: PaginationProps) => {
        setOffset((data.activePage as number - 1) * listItemLimit);
    };

    /**
     * Handles sort order change.
     *
     * @param {boolean} isAscending.
     */
    const handleSortOrderChange = (isAscending: boolean) => {
        setSortOrder(isAscending);
    };

    /**
     * Handle sort strategy change.
     *
     * @param {React.SyntheticEvent<HTMLElement>} event.
     * @param {DropdownProps} data.
     */
    const handleSortStrategyChange = (event: React.SyntheticEvent<HTMLElement>, data: DropdownProps) => {
        setSortBy(SORT_BY.filter(option => option.value === data.value)[ 0 ]);
    };

    /**
     * Handles the `onFilter` callback action from the search component.
     *
     * @param {string} query - Search query.
     */
    const handleUserstoreFilter = (query: string): void => {
        try {
            // TODO: Implement once the API is ready
            // fetchUserStores(null, null, null, query);
            setFilteredUserStores(filterList(userStores, query, "name", true));
            setSearchQuery(query);
            setOffset(0);
            setResetPagination();
        } catch (error) {
            dispatch(addAlert({
                description: error.message,
                level: AlertLevels.ERROR,
                message: t("devPortal:components.userstores.advancedSearch.error")
            }));
        }
    };

    /**
     * Handles the `onSearchQueryClear` callback action.
     */
    const handleSearchQueryClear = (): void => {
        setTriggerClearQuery(!triggerClearQuery);
        setSearchQuery("");
        setFilteredUserStores(userStores);
    };

    return (
        <PageLayout
            isLoading={ isLoading }
            title={ t("devPortal:components.userstores.pageLayout.list.title") }
            description={ t("devPortal:components.userstores.pageLayout.list.description") }
            showBottomDivider={ true }
            data-testid={ `${ testId }-page-layout` }
        >
            <ListLayout
                advancedSearch={
                    <AdvancedSearchWithBasicFilters
                        onFilter={ handleUserstoreFilter }
                        filterAttributeOptions={ [
                            {
                                key: 0,
                                text: t("common:name"),
                                value: "name"
                            },
                            {
                                key: 1,
                                text: t("common:description"),
                                value: "description"
                            }
                        ] }
                        filterAttributePlaceholder={
                            t("devPortal:components.userstores.advancedSearch.form.inputs" +
                                ".filterAttribute.placeholder")
                        }
                        filterConditionsPlaceholder={
                            t("devPortal:components.userstores.advancedSearch.form.inputs" +
                                ".filterCondition.placeholder")
                        }
                        filterValuePlaceholder={
                            t("devPortal:components.userstores.advancedSearch.form.inputs" +
                                ".filterValue.placeholder")
                        }
                        placeholder={
                            t("devPortal:components.userstores.advancedSearch.placeholder")
                        }
                        defaultSearchAttribute="name"
                        defaultSearchOperator="co"
                        triggerClearQuery={ triggerClearQuery }
                        data-testid={ `${ testId }-advanced-search` }
                    />
                }
                currentListSize={ listItemLimit }
                listItemLimit={ listItemLimit }
                onItemsPerPageDropdownChange={ handleItemsPerPageDropdownChange }
                onPageChange={ handlePaginationChange }
                onSortStrategyChange={ handleSortStrategyChange }
                onSortOrderChange={ handleSortOrderChange }
                resetPagination={ resetPagination }
                rightActionPanel={
                    hasRequiredScopes(
                        featureConfig?.userStores,
                        featureConfig?.userStores?.scopes?.create) && (
                        <PrimaryButton
                            onClick={ () => {
                                history.push(USERSTORE_TEMPLATES_PATH);
                            } }
                            data-testid={ `${ testId }-list-layout-add-button` }
                        >
                            <Icon name="add" />
                            { t("devPortal:components.userstores.pageLayout.list.primaryAction")}
                        </PrimaryButton>
                    )
                }
                leftActionPanel={ null }
                showPagination={ true }
                sortOptions={ SORT_BY }
                sortStrategy={ sortBy }
                showTopActionPanel={ isLoading || !(!searchQuery && filteredUserStores?.length <= 0) }
                totalPages={ Math.ceil(filteredUserStores?.length / listItemLimit) }
                totalListSize={ filteredUserStores?.length }
                data-testid={ `${ testId }-list-layout` }
            >
                <UserStoresList
                    isLoading={ isLoading }
                    list={ paginate(filteredUserStores, listItemLimit, offset) }
                    onEmptyListPlaceholderActionClick={ () => history.push(USERSTORE_TEMPLATES_PATH) }
                    onSearchQueryClear={ handleSearchQueryClear }
                    searchQuery={ searchQuery }
                    update={ fetchUserStores }
                    featureConfig={ featureConfig }
                    data-testid={ `${ testId }-list` }
                />
            </ListLayout>
        </PageLayout>
    );
};

/**
 * Default props for the component.
 */
UserStores.defaultProps = {
    "data-testid": "userstores"
};
