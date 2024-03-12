/**
 * Copyright (c) 2021-2024, WSO2 LLC. (https://www.wso2.com).
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

import {
    Confirmation,
    DangerZone,
    EditPage,
    FormAttributes,
    FormField,
    HelpPanelInterface,
    InfoModal,
    Message,
    ModalInterface,
    Notification,
    NotificationItem,
    Page,
    Placeholder,
    Popup,
    TransferList
} from "@wso2is/i18n";

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface IdentityProviders {
    console: {
        applicationRoles: {
            assign: string;
            assignGroupWizard: {
                heading: string;
                subHeading: string;
            };
            authenticatorGroups: {
                goToConnections: string;
                groupsList: {
                    assignGroups: string;
                    notifications: {
                        fetchAssignedGroups: Notification;
                        updateAssignedGroups: Notification;
                    };
                };
                hint: string;
                placeholder: {
                    title: string;
                    subTitle: {
                        0: string;
                        1: string;
                    };
                };
            };
            connectorGroups: {
                placeholder: {
                    title: string;
                    subTitle: {
                        0: string;
                        1: string;
                    };
                };
            };
            heading: string;
            subHeading: string;
            roleGroups: {
                assignGroup: string;
                searchGroup: string;
                placeholder: {
                    title: string;
                    subTitle: {
                        0: string;
                        1: string;
                    };
                };
                notifications: {
                    addGroups: Notification;
                    fetchGroups: Notification;
                };
                confirmation: {
                    deleteRole: {
                        message: string;
                        content: string;
                    };
                };
            };
            roleList: {
                placeholder: {
                    title: string;
                    subTitle: {
                        0: string;
                        1: string;
                    };
                };
            };
            roleMapping: {
                heading: string;
                subHeading: string;
                notifications: {
                    sharedApplication: {
                        error: NotificationItem;
                    };
                    updateRole: Notification;
                };
            };
            roles: {
                heading: string;
                subHeading: string;
                goBackToRoles: string;
                orgRoles: {
                    heading: string;
                    subHeading: string;
                };
            };
            searchApplication: string;
        };
        identityProviderGroups: {
            claimConfigs: {
                groupAttributeLabel: string;
                groupAttributeHint: string;
                groupAttributePlaceholder: string;
                groupAttributeMessage1: string;
                groupAttributeMessage2: string;
                groupAttributeMessageOIDC: string;
                groupAttributeMessageSAML: string;
                notifications: {
                    fetchConfigs: Notification;
                };
            };
            createGroupWizard: {
                groupNameLabel: string;
                groupNamePlaceHolder: string;
                groupNameHint: string;
                subHeading: string;
                notifications: {
                    createIdentityProviderGroup: Notification;
                    duplicateGroupError: Notification;
                };
            };
            groupsList: {
                confirmation: {
                    deleteGroup: {
                        message: string;
                        content: string;
                    };
                };
                newGroup: string;
                noGroupsAvailable: string;
                notifications: {
                    fetchGroups: Notification;
                    deleteGroup: Notification;
                };
                searchByName: string;
            };
        };
    };
    develop: {
        emailProviders: {
            configureEmailTemplates: string;
            heading: string;
            subHeading: string;
            description: string;
            note: string;
            info: string;
            updateButton: string;
            sendTestMailButton: string;
            goBack: string;
            confirmationModal: {
                header: string;
                message: string;
                content: string;
                assertionHint: string;
            };
            dangerZoneGroup: {
                header: string;
                revertConfig: {
                    heading: string;
                    subHeading: string;
                    actionTitle: string;
                };
            };
            form: {
                smtpServerHost: {
                    label: string;
                    placeholder: string;
                    hint: string;
                };
                smtpPort: {
                    label: string;
                    placeholder: string;
                    hint: string;
                };
                fromAddress: {
                    label: string;
                    placeholder: string;
                    hint: string;
                };
                replyToAddress: {
                    label: string;
                    placeholder: string;
                    hint: string;
                };
                userName: {
                    label: string;
                    placeholder: string;
                    hint: string;
                };
                password: {
                    label: string;
                    placeholder: string;
                    hint: string;
                };
                displayName: {
                    label: string;
                    placeholder: string;
                    hint: string;
                };
                validations: {
                    required: string;
                    portInvalid: string;
                    emailInvalid: string;
                };
            };
            notifications: {
                getConfiguration: {
                    error: {
                        description: string;
                        message: string;
                    };
                };
                deleteConfiguration: {
                    success: {
                        description: string;
                        message: string;
                    };
                    error: {
                        description: string;
                        message: string;
                    };
                };
                updateConfiguration: {
                    success: {
                        description: string;
                        message: string;
                    };
                    error: {
                        description: string;
                        message: string;
                    };
                };
            };
        };
        features: {
            applications: {
                addWizard: {
                    steps: {
                        generalSettings: {
                            heading: string;
                        };
                        protocolConfig: {
                            heading: string;
                        };
                        protocolSelection: {
                            heading: string;
                        };
                        summary: {
                            heading: string;
                            sections: {
                                accessURL: {
                                    heading: string;
                                };
                                applicationQualifier: {
                                    heading: string;
                                };
                                assertionURLs: {
                                    heading: string;
                                };
                                audience: {
                                    heading: string;
                                };
                                callbackURLs: {
                                    heading: string;
                                };
                                certificateAlias: {
                                    heading: string;
                                };
                                discoverable: {
                                    heading: string;
                                };
                                grantType: {
                                    heading: string;
                                };
                                issuer: {
                                    heading: string;
                                };
                                metaFile: {
                                    heading: string;
                                };
                                metadataURL: {
                                    heading: string;
                                };
                                public: {
                                    heading: string;
                                };
                                realm: {
                                    heading: string;
                                };
                                renewRefreshToken: {
                                    heading: string;
                                };
                                replyTo: {
                                    heading: string;
                                };
                            };
                        };
                    };
                };
                advancedSearch: {
                    form: {
                        inputs: {
                            filterAttribute: {
                                placeholder: string;
                            };
                            filterCondition: {
                                placeholder: string;
                            };
                            filterValue: {
                                placeholder: string;
                            };
                        };
                    };
                    placeholder: string;
                };
                confirmations: {
                    addSocialLogin: Popup;
                    changeProtocol: Confirmation;
                    deleteApplication: Confirmation;
                    deleteChoreoApplication: Confirmation;
                    deleteOutboundProvisioningIDP: Confirmation;
                    deleteProtocol: Confirmation;
                    handlerAuthenticatorAddition: Confirmation;
                    backupCodeAuthenticatorDelete: Confirmation;
                    lowOIDCExpiryTimes: Confirmation;
                    regenerateSecret: Confirmation;
                    reactivateSPA: Confirmation;
                    reactivateOIDC: Confirmation;
                    removeApplicationUserAttribute: Popup;
                    removeApplicationUserAttributeMapping: Popup;
                    revokeApplication: Confirmation;
                    clientSecretHashDisclaimer: {
                        modal: Confirmation;
                        forms: {
                            clientIdSecretForm: {
                                clientId: FormAttributes;
                                clientSecret: FormAttributes;
                            };
                        };
                    };
                    certificateDelete: Confirmation & Record<string, string>;
                };
                dangerZoneGroup: {
                    header: string;
                    deleteApplication: DangerZone;
                };
                edit: {
                    sections: {
                        access: {
                            addProtocolWizard: {
                                heading: string;
                                subHeading: string;
                                steps: {
                                    protocolSelection: {
                                        manualSetup: {
                                            emptyPlaceholder: Placeholder;
                                            heading: string;
                                            subHeading: string;
                                        };
                                        quickSetup: {
                                            emptyPlaceholder: Placeholder;
                                            heading: string;
                                            subHeading: string;
                                        };
                                    };
                                };
                            };
                            tabName: string;
                            protocolLanding: {
                                heading: string;
                                subHeading: string;
                            };
                        };
                        advanced: {
                            tabName: string;
                        };
                        attributes: {
                            forms: {
                                fields: {
                                    dynamic: {
                                        localRole: FormAttributes;
                                        applicationRole: FormAttributes;
                                    };
                                };
                            };
                            selection: {
                                addWizard: {
                                    header: string;
                                    subHeading: string;
                                    steps: {
                                        select: {
                                            transfer: TransferList;
                                        };
                                    };
                                };
                                heading: string;
                                scopelessAttributes: {
                                    description: string;
                                    displayName: string;
                                    name: string;
                                    hint: string;
                                };
                                selectedScopesComponentHint: string;
                                howToUseScopesHint: string;
                                attributeComponentHint: string;
                                attributeComponentHintAlt: string;
                                description: string;
                                mandatoryAttributeHint: string;
                                mappingTable: {
                                    actions: {
                                        enable: string;
                                    };
                                    columns: {
                                        appAttribute: string;
                                        attribute: string;
                                        mandatory: string;
                                        requested: string;
                                    };
                                    mappedAtributeHint: string;
                                    mappingRevert: {
                                        confirmationHeading: string;
                                        confirmationMessage: string;
                                        confirmationContent: string;
                                        confirmPrimaryAction: string;
                                        confirmSecondaryAction: string;
                                    };
                                    listItem: {
                                        actions: {
                                            makeMandatory: string;
                                            makeRequested: string;
                                            makeScopeRequested: string;
                                            removeMandatory: string;
                                            removeRequested: string;
                                            removeScopeRequested: string;
                                            subjectDisabledSelection: string;
                                        };
                                        faultyAttributeMapping: string;
                                        faultyAttributeMappingHint: string;
                                        fields: {
                                            claim: FormAttributes;
                                        };
                                    };
                                    searchPlaceholder: string;
                                };
                                selectAll: string;
                            };
                            attributeMappingChange: Notification;
                            emptySearchResults: {
                                subtitles: {
                                    0: string;
                                    1: string;
                                };
                                title: string;
                            };
                            roleMapping: {
                                heading: string;
                            };
                            tabName: string;
                        };
                        info: {
                            oidcHeading: string;
                            oidcSubHeading: string;
                            samlHeading: string;
                            samlSubHeading: string;
                            wsFedHeading: string;
                            wsFedSubHeading: string;
                            tabName: string;
                        };
                        general: {
                            tabName: string;
                        };
                        protocol: {
                            title: string;
                            subtitle: string;
                            button: string;
                        };
                        provisioning: {
                            tabName: string;
                            inbound: {
                                heading: string;
                                subHeading: string;
                            };
                            outbound: {
                                actions: {
                                    addIdp: string;
                                };
                                addIdpWizard: {
                                    heading: string;
                                    subHeading: string;
                                    steps: {
                                        details: string;
                                    };
                                    errors: {
                                        noProvisioningConnector: string;
                                    };
                                };
                                heading: string;
                                subHeading: string;
                            };
                        };
                        signOnMethod: {
                            tabName: string;
                            sections: {
                                authenticationFlow: {
                                    heading: string;
                                    sections: {
                                        scriptBased: {
                                            accordion: {
                                                title: {
                                                    description: string;
                                                    heading: string;
                                                };
                                            };
                                            conditionalAuthTour: {
                                                steps: {
                                                    0: {
                                                        heading: string;
                                                        content: {
                                                            0: string;
                                                            1: string;
                                                        };
                                                    };
                                                    1: {
                                                        heading: string;
                                                        content: {
                                                            0: string;
                                                        };
                                                    };
                                                    2: {
                                                        heading: string;
                                                        content: {
                                                            0: string;
                                                        };
                                                    };
                                                };
                                            };
                                            heading: string;
                                            hint: string;
                                            editor: {
                                                apiDocumentation: string;
                                                changeConfirmation: {
                                                    content: string;
                                                    heading: string;
                                                    message: string;
                                                };
                                                goToApiDocumentation: string;
                                                resetConfirmation: {
                                                    content: string;
                                                    heading: string;
                                                    message: string;
                                                };
                                                templates: {
                                                    heading: string;
                                                    darkMode: string;
                                                };
                                            };
                                            secretsList: {
                                                create: string;
                                                emptyPlaceholder: string;
                                                search: string;
                                                tooltips: {
                                                    keyIcon: string;
                                                    plusIcon: string;
                                                };
                                            };
                                        };
                                        stepBased: {
                                            actions: {
                                                addAuthentication: string;
                                                addNewStep: string;
                                                addStep: string;
                                                selectAuthenticator: string;
                                            };
                                            addAuthenticatorModal: ModalInterface;
                                            heading: string;
                                            hint: string;
                                            forms: {
                                                fields: {
                                                    attributesFrom: FormAttributes;
                                                    subjectIdentifierFrom: FormAttributes;
                                                    enableBackupCodes: FormAttributes;
                                                };
                                            };
                                            secondFactorDisabled: string;
                                            secondFactorDisabledDueToProxyMode: string;
                                            secondFactorDisabledInFirstStep: string;
                                            backupCodesDisabled: string;
                                            backupCodesDisabledInFirstStep: string;
                                            authenticatorDisabled: string;
                                            firstFactorDisabled: string;
                                            federatedSMSOTPConflictNote: {
                                                multipleIdps: string;
                                                singleIdp: string;
                                            };
                                            sessionExecutorDisabledInFirstStep: string;
                                            sessionExecutorDisabledInMultiOptionStep: string;
                                        };
                                    };
                                };
                                customization: {
                                    heading: string;
                                    revertToDefaultButton: {
                                        hint: string;
                                        label: string;
                                    };
                                };
                                landing: {
                                    defaultConfig: {
                                        description: {
                                            0: string;
                                            1: string;
                                        };
                                        heading: string;
                                    };
                                    flowBuilder: {
                                        addMissingSocialAuthenticatorModal: ModalInterface;
                                        duplicateSocialAuthenticatorSelectionModal: ModalInterface;
                                        heading: string;
                                        headings: {
                                            default: string;
                                            socialLogin: string;
                                            multiFactorLogin: string;
                                            passwordlessLogin: string;
                                        };
                                        types: {
                                            apple: {
                                                description: string;
                                                heading: string;
                                            };
                                            defaultConfig: {
                                                description: string;
                                                heading: string;
                                            };
                                            facebook: {
                                                description: string;
                                                heading: string;
                                            };
                                            github: {
                                                description: string;
                                                heading: string;
                                            };
                                            google: {
                                                description: string;
                                                heading: string;
                                            };
                                            idf: {
                                                tooltipText: string;
                                            };
                                            totp: {
                                                description: string;
                                                heading: string;
                                            };
                                            usernameless: {
                                                description: string;
                                                heading: string;
                                                info: string;
                                            };
                                            passkey: {
                                                description: string;
                                                heading: string;
                                                info: {
                                                    progressiveEnrollmentEnabled: string;
                                                    passkeyAsFirstStepWhenprogressiveEnrollmentEnabled: string;
                                                    passkeyIsNotFirstStepWhenprogressiveEnrollmentEnabled: string;
                                                    progressiveEnrollmentEnabledCheckbox: string;
                                                    progressiveEnrollmentDisabled: string;
                                                };
                                            };
                                            magicLink: {
                                                description: string;
                                                heading: string;
                                            };
                                            microsoft: {
                                                description: string;
                                                heading: string;
                                            };
                                            emailOTP: {
                                                description: string;
                                                heading: string;
                                            };
                                            smsOTP: {
                                                description: string;
                                                heading: string;
                                            };
                                            emailOTPFirstFactor: {
                                                description: string;
                                                heading: string;
                                            };
                                        };
                                    };
                                };
                                requestPathAuthenticators: {
                                    title: string;
                                    subTitle: string;
                                    notifications: {
                                        getRequestPathAuthenticators: Notification;
                                    };
                                };
                                templateDescription: {
                                    popupContent: string;
                                    description: {
                                        prerequisites: string;
                                        parameters: string;
                                        description: string;
                                        defaultSteps: string;
                                        helpReference: string;
                                        code: string;
                                    };
                                };
                            };
                        };
                        sharedAccess: {
                            subTitle: string;
                            tabName: string;
                        };
                        shareApplication: {
                            heading: string;
                            shareApplication: string;
                            addSharingNotification: Notification;
                            stopSharingNotification: Notification;
                            getSharedOrganizations: Notification;
                            stopAllSharingNotification: Notification;
                            switchToSelectiveShareFromSharingWithAllSuborgsWarning: string;
                        };
                        apiAuthorization: {
                            m2mPolicyMessage: string;
                        };
                        roles: {
                            createApplicationRoleWizard: {
                                title: string;
                                subTitle: string;
                                button: string;
                            };
                        };
                    };
                };
                forms: {
                    advancedAttributeSettings: {
                        sections: {
                            linkedAccounts: {
                                errorAlert: {
                                    message: string;
                                    description: string;
                                };
                                heading: string;
                                descriptionFederated: string;
                                fields: {
                                    validateLocalAccount: FormAttributes;
                                    mandateLocalAccount: FormAttributes;
                                };
                            };
                            subject: {
                                fields: {
                                    alternateSubjectAttribute: FormAttributes;
                                    subjectAttribute: FormAttributes;
                                    subjectIncludeTenantDomain: FormAttributes;
                                    subjectIncludeUserDomain: FormAttributes;
                                    subjectUseMappedLocalSubject: FormAttributes;
                                    subjectType: FormAttributes;
                                    sectorIdentifierURI: FormAttributes;
                                };
                                heading: string;
                            };
                            role: {
                                heading: string;
                                fields: {
                                    roleAttribute: FormAttributes;
                                    role: FormAttributes;
                                };
                            };
                        };
                    };
                    advancedConfig: {
                        fields: {
                            enableAuthorization: FormAttributes;
                            returnAuthenticatedIdpList: FormAttributes;
                            saas: FormAttributes;
                            skipConsentLogin: FormAttributes;
                            skipConsentLogout: FormAttributes;
                        };
                        sections: {
                            applicationNativeAuthentication: {
                                heading: string;
                                alerts: {
                                    clientAttestation: string;
                                };
                                fields: {
                                    enableAPIBasedAuthentication: FormAttributes;
                                    enableClientAttestation: FormAttributes;
                                    android: {
                                        heading: string;
                                        fields: {
                                            androidPackageName: FormAttributes;
                                            androidAttestationServiceCredentials: FormAttributes;
                                        };
                                    };
                                    apple: {
                                        heading: string;
                                        fields: {
                                            appleAppId: FormAttributes;
                                        };
                                    };
                                };
                            };
                            certificate: {
                                heading: string;
                                hint?: {
                                    customOidc: string;
                                    customPassiveSTS: string;
                                    customSaml: string;
                                };
                                fields: {
                                    jwksValue: FormAttributes;
                                    pemValue: FormAttributes;
                                    type: FormAttributes;
                                };
                                invalidOperationModal?: {
                                    header: string;
                                    message: string;
                                };
                            };
                        };
                    };
                    generalDetails: {
                        fields: {
                            name: FormAttributes;
                            description: FormAttributes;
                            imageUrl: FormAttributes;
                            discoverable: FormAttributes;
                            accessUrl: FormAttributes;
                            isSharingEnabled: FormAttributes;
                            isManagementApp: FormAttributes;
                            isFapiApp: FormAttributes;
                        };
                        managementAppBanner: string;
                    };
                    inboundCustom: {
                        fields: {
                            checkbox: FormAttributes;
                            dropdown: FormAttributes;
                            generic: FormAttributes;
                            password: FormAttributes;
                        };
                    };
                    inboundOIDC: {
                        description: string;
                        documentation: string;
                        fields: {
                            allowedOrigins: FormAttributes;
                            callBackUrls: FormAttributes;
                            clientID: FormAttributes;
                            clientSecret: FormAttributes;
                            grant: FormAttributes;
                            public: FormAttributes;
                        };
                        mobileApp: {
                            discoverableHint: string;
                            mobileAppPlaceholder: string;
                        };
                        dropdowns: {
                            selectOption: string;
                        };
                        sections: {
                            accessToken: {
                                heading: string;
                                hint: string;
                                fields: {
                                    bindingType: FormAttributes;
                                    expiry: FormAttributes;
                                    applicationTokenExpiry: FormAttributes;
                                    type: FormAttributes;
                                    revokeToken: FormAttributes;
                                    validateBinding: FormAttributes;
                                    audience: FormAttributes;
                                };
                            };
                            idToken: {
                                heading: string;
                                fields: {
                                    expiry: FormAttributes;
                                    algorithm: FormAttributes;
                                    audience: FormAttributes;
                                    encryption: FormAttributes;
                                    signing: FormAttributes;
                                    method: FormAttributes;
                                };
                            };
                            logoutURLs: {
                                heading: string;
                                fields: {
                                    back: FormAttributes;
                                    front: FormAttributes;
                                };
                            };
                            pkce: {
                                description: string;
                                heading: string;
                                hint: string;
                                fields: {
                                    pkce: FormAttributes;
                                };
                            };
                            clientAuthentication: {
                                heading: string;
                                fields: {
                                    authenticationMethod: FormAttributes;
                                    signingAlgorithm: FormAttributes;
                                    subjectDN: FormAttributes;
                                };
                            };
                            pushedAuthorization: {
                                heading: string;
                                fields: {
                                    requirePushAuthorizationRequest: FormAttributes;
                                };
                            };
                            requestObject: {
                                heading: string;
                                fields: {
                                    requestObjectSigningAlg: FormAttributes;
                                    requestObjectEncryptionAlgorithm: FormAttributes;
                                    requestObjectEncryptionMethod: FormAttributes;
                                };
                            };
                            refreshToken: {
                                heading: string;
                                fields: {
                                    expiry: FormAttributes;
                                    renew: FormAttributes;
                                };
                            };
                            requestObjectSignature: {
                                heading: string;
                                description: string;
                                fields: {
                                    signatureValidation: FormAttributes;
                                };
                            };
                            scopeValidators: {
                                heading: string;
                                fields: {
                                    validator: FormAttributes;
                                };
                            };
                            certificates: {
                                disabledPopup: string;
                            };
                        };
                        messages: {
                            revokeDisclaimer: Message;
                            customInvalidMessage: string;
                        };
                    };
                    inboundSAML: {
                        description: string;
                        documentation: string;
                        fields: {
                            assertionURLs: FormAttributes;
                            defaultAssertionURL: FormAttributes;
                            idpEntityIdAlias: FormAttributes;
                            issuer: FormAttributes;
                            metaURL: FormAttributes;
                            mode: FormAttributes;
                            qualifier: FormAttributes;
                        };
                        sections: {
                            assertion: {
                                heading: string;
                                fields: {
                                    audience: FormAttributes;
                                    nameIdFormat: FormAttributes;
                                    recipients: FormAttributes;
                                };
                            };
                            attributeProfile: {
                                heading: string;
                                fields: {
                                    enable: FormAttributes;
                                    includeAttributesInResponse: FormAttributes;
                                    serviceIndex: FormAttributes;
                                };
                            };
                            encryption: {
                                heading: string;
                                fields: {
                                    assertionEncryption: FormAttributes;
                                    assertionEncryptionAlgorithm: FormAttributes;
                                    keyEncryptionAlgorithm: FormAttributes;
                                };
                            };
                            idpInitiatedSLO: {
                                heading: string;
                                fields: {
                                    enable: FormAttributes;
                                    returnToURLs: FormAttributes;
                                };
                            };
                            responseSigning: {
                                heading: string;
                                fields: {
                                    digestAlgorithm: FormAttributes;
                                    responseSigning: FormAttributes;
                                    signingAlgorithm: FormAttributes;
                                };
                            };
                            requestProfile: {
                                heading: string;
                                fields: {
                                    enable: FormAttributes;
                                };
                            };
                            requestValidation: {
                                heading: string;
                                fields: {
                                    signatureValidation: FormAttributes;
                                    signatureValidationCertAlias: FormAttributes;
                                };
                            };
                            sloProfile: {
                                heading: string;
                                fields: {
                                    enable: FormAttributes;
                                    logoutMethod: FormAttributes;
                                    requestURL: FormAttributes;
                                    responseURL: FormAttributes;
                                };
                            };
                            ssoProfile: {
                                heading: string;
                                fields: {
                                    artifactBinding: FormAttributes;
                                    bindings: FormAttributes;
                                    idpInitiatedSSO: FormAttributes;
                                };
                            };
                            certificates: {
                                disabledPopup: string;
                                certificateRemoveConfirmation: {
                                    header: string;
                                    content: string;
                                };
                            };
                        };
                    };
                    inboundSTS: {
                        fields: {
                            realm: FormAttributes;
                            replyTo: FormAttributes;
                            replyToLogout: FormAttributes;
                        };
                    };
                    inboundWSTrust: {
                        fields: {
                            audience: FormAttributes;
                            certificateAlias: FormAttributes;
                        };
                    };
                    outboundProvisioning: {
                        fields: {
                            blocking: FormAttributes;
                            connector: FormAttributes;
                            idp: FormAttributes;
                            jit: FormAttributes;
                            rules: FormAttributes;
                        };
                    };
                    provisioningConfig: {
                        fields: {
                            proxyMode: FormAttributes;
                            userstoreDomain: FormAttributes;
                        };
                    };
                    spaProtocolSettingsWizard: {
                        fields: {
                            callBackUrls: FormAttributes;
                            name: FormAttributes;
                            urlDeepLinkError: string;
                        };
                    };
                };
                helpPanel: HelpPanelInterface;
                list: {
                    columns: {
                        actions: string;
                        name: string;
                        inboundKey: string;
                    };
                    actions: {
                        add: string;
                        predefined: string;
                        custom: string;
                    };
                    labels: {
                        fragment: string;
                    };
                };
                myaccount: {
                    title: string;
                    description: string;
                    popup: string;
                    enable: {
                        0: string;
                        1: string;
                    };
                    Confirmation: {
                        enableConfirmation: {
                            content: string;
                            heading: string;
                            message: string;
                        };
                        disableConfirmation: {
                            content: string;
                            heading: string;
                            message: string;
                        };
                    };
                    notifications: {
                        error: {
                            description: string;
                            message: string;
                        };
                        genericError: {
                            description: string;
                            message: string;
                        };
                        success: {
                            description: string;
                            message: string;
                        };
                    };
                    fetchMyAccountStatus: {
                        error: {
                            description: string;
                            message: string;
                        };
                        genericError: {
                            description: string;
                            message: string;
                        };
                    };
                };
                notifications: {
                    addApplication: Notification;
                    apiLimitReachedError: Notification;
                    authenticationStepMin: Notification;
                    authenticationStepDeleteErrorDueToSecondFactors: Notification;
                    authenticationStepDeleteErrorDueToAppShared: Notification;
                    deleteApplication: Notification;
                    deleteOptionErrorDueToSecondFactorsOnRight: Notification;
                    deleteProtocolConfig: Notification;
                    duplicateAuthenticationStep: Notification;
                    emptyAuthenticationStep: Notification;
                    fetchAllowedCORSOrigins: Notification;
                    fetchApplication: Notification;
                    fetchMyAccountApplication: Notification;
                    fetchApplications: Notification;
                    fetchCustomInboundProtocols: Notification;
                    fetchInboundProtocols: Notification;
                    fetchProtocolMeta: Notification;
                    fetchSAMLIDPConfigs: Notification;
                    fetchOIDCIDPConfigs: Notification;
                    fetchTemplate: Notification;
                    fetchTemplates: Notification;
                    getInboundProtocolConfig: Notification;
                    regenerateSecret: Notification;
                    revokeApplication: Notification;
                    tierLimitReachedError: {
                        emptyPlaceholder: Placeholder;
                        heading: string;
                    };
                    updateAdvancedConfig: Notification;
                    updateApplication: Notification;
                    updateAuthenticationFlow: Notification;
                    updateClaimConfig: Notification;
                    updateInboundProtocolConfig: Notification;
                    updateInboundProvisioningConfig: Notification;
                    updateOutboundProvisioning: Notification;
                    updateProtocol: Notification;
                    fetchOIDCServiceEndpoints: Notification;
                    secondFactorAuthenticatorToFirstStep: Notification;
                    firstFactorAuthenticatorToSecondStep: Notification;
                    conditionalScriptLoopingError: NotificationItem;
                    deleteCertificateSuccess: NotificationItem;
                    deleteCertificateGenericError: NotificationItem;
                    updateOnlyIdentifierFirstError: NotificationItem;
                    updateIdentifierFirstInFirstStepError: NotificationItem;
                };
                popups: {
                    appStatus: {
                        active: Popup;
                        notConfigured: Popup;
                        revoked: Popup;
                    };
                };
                placeholders: {
                    emptyAttributesList: Placeholder;
                    emptyAuthenticatorStep: Placeholder;
                    emptyAuthenticatorsList: Placeholder;
                    emptyOutboundProvisioningIDPs: Placeholder;
                    emptyList: Placeholder;
                    emptyProtocolList: Placeholder;
                };
                resident: {
                    provisioning: {
                        outbound: {
                            actions: {
                                addIdp: string;
                            };
                            addIdpWizard: {
                                heading: string;
                                subHeading: string;
                                steps: {
                                    details: string;
                                };
                            };
                            emptyPlaceholder: Placeholder;
                            form: {
                                fields: {
                                    connection: {
                                        label: string;
                                        placeholder: string;
                                        validations: {
                                            empty: string;
                                        };
                                    };
                                };
                            };
                            heading: string;
                            subHeading: string;
                            notifications: {
                                create: Notification;
                                delete: Notification;
                                fetch: Notification;
                                update: Notification;
                            };
                        };
                    };
                };
                templates: {
                    manualSetup: {
                        heading: string;
                        subHeading: string;
                    };
                    quickSetup: {
                        heading: string;
                        subHeading: string;
                    };
                };
                wizards: {
                    minimalAppCreationWizard: {
                        help: {
                            heading: string;
                            subHeading: string;
                            template: FormAttributes;
                        };
                    };
                    applicationCertificateWizard: {
                        heading: string;
                        subHeading: string;
                        emptyPlaceHolder: {
                            title: string;
                            description1: string;
                            description2: string;
                        };
                    };
                };
            };
            authenticationProvider?: {
                advancedSearch?: {
                    form: {
                        inputs: {
                            filterAttribute: {
                                placeholder: string;
                            };
                            filterCondition: {
                                placeholder: string;
                            };
                            filterValue: {
                                placeholder: string;
                            };
                        };
                    };
                    placeholder: string;
                };
                buttons?: {
                    addIDP: string;
                    addAuthenticator: string;
                    addConnector: string;
                    addAttribute: string;
                    addCertificate: string;
                };
                confirmations?: {
                    deleteIDP: Confirmation;
                    deleteIDPWithConnectedApps: Confirmation;
                    deleteAuthenticator: Confirmation;
                    deleteConnector: Confirmation;
                    deleteCertificate: Confirmation;
                };
                dangerZoneGroup?: {
                    header: string;
                    disableIDP: DangerZone;
                    deleteIDP: DangerZone;
                };
                edit?: {
                    common: {
                        settings: {
                            tabName: string;
                        };
                    };
                    emailOTP: {
                        emailTemplate: {
                            tabName: string;
                        };
                    };
                    smsOTP: {
                        smsProvider: {
                            tabName: string;
                        };
                    };
                };
                forms?: {
                    advancedConfigs?: {
                        federationHub: FormAttributes;
                        homeRealmIdentifier: FormAttributes;
                        alias: FormAttributes;
                        certificateType: {
                            label: string;
                            hint: string;
                            certificatePEM: FormAttributes;
                            certificateJWKS: FormAttributes;
                        };
                    };
                    attributeSettings?: {
                        attributeMapping: {
                            attributeColumnHeader: string;
                            attributeMapColumnHeader: string;
                            attributeMapInputPlaceholderPrefix: string;
                            componentHeading: string;
                            hint: string;
                        };
                        attributeProvisioning: {
                            attributeColumnHeader: {
                                0: string;
                                1: string;
                            };
                            attributeMapColumnHeader: string;
                            attributeMapInputPlaceholderPrefix: string;
                            componentHeading: string;
                            hint: string;
                        };
                        attributeListItem: {
                            validation: {
                                empty: string;
                            };
                        };
                        attributeSelection: {
                            searchAttributes: {
                                placeHolder: string;
                            };
                        };
                    };
                    authenticatorAccordion?: {
                        default: {
                            0: string;
                            1: string;
                        };
                        enable: {
                            0: string;
                            1: string;
                        };
                    };
                    authenticatorSettings?: {
                        apple: {
                            additionalQueryParameters: FormAttributes;
                            callbackUrl: FormAttributes;
                            clientId: FormAttributes;
                            keyId: FormAttributes;
                            privateKey: FormAttributes;
                            secretValidityPeriod: FormAttributes;
                            scopes: {
                                heading: string;
                                hint: string;
                                list: {
                                    email: {
                                        description: string;
                                    };
                                    name: {
                                        description: string;
                                    };
                                };
                            };
                            teamId: FormAttributes;
                        };
                        emailOTP: {
                            enableBackupCodes: {
                                hint: string;
                                label: string;
                                validations: {
                                    required: string;
                                };
                            };
                            expiryTime: {
                                hint: string;
                                label: string;
                                placeholder: string;
                                validations: {
                                    invalid: string;
                                    range: string;
                                    required: string;
                                };
                                unit: string;
                            };
                            tokenLength: {
                                hint: string;
                                label: string;
                                unit: {
                                    digits: string;
                                    characters: string;
                                };
                                placeholder: string;
                                validations: {
                                    invalid: string;
                                    range: {
                                        digits: string;
                                        characters: string;
                                    };
                                    required: string;
                                };
                            };
                            useAlphanumericChars: {
                                hint: string;
                                label: string;
                                validations: {
                                    required: string;
                                };
                            };
                        };
                        smsOTP: {
                            hint: string;
                            expiryTime: {
                                hint: string;
                                label: string;
                                placeholder: string;
                                validations: {
                                    invalid: string;
                                    range: string;
                                    required: string;
                                };
                                unit: string;
                            };
                            tokenLength: {
                                hint: string;
                                label: string;
                                placeholder: string;
                                validations: {
                                    invalid: string;
                                    range: {
                                        digits: string;
                                        characters: string;
                                    };
                                    required: string;
                                };
                                unit: {
                                    digits: string;
                                    characters: string;
                                };
                            };
                            useNumericChars: {
                                hint: string;
                                label: string;
                                validations: {
                                    required: string;
                                };
                            };
                            allowedResendAttemptCount: {
                                hint: string;
                                label: string;
                                placeholder: string;
                                validations: {
                                    required: string;
                                    invalid: string;
                                    range: string;
                                };
                            };
                        };
                        fido2: {
                            allowProgressiveEnrollment: {
                                hint: string;
                                label: string;
                            };
                            allowUsernamelessAuthentication: {
                                hint: string;
                                label: string;
                            };
                        };
                        facebook: {
                            callbackUrl: FormAttributes;
                            clientId: FormAttributes;
                            clientSecret: FormAttributes;
                            scopes: {
                                heading: string;
                                hint: string;
                                list: {
                                    email: {
                                        description: string;
                                    };
                                    profile: {
                                        description: string;
                                    };
                                };
                            };
                            userInfo: {
                                heading: string;
                                hint: string;
                                placeholder: string;
                                list: {
                                    ageRange: {
                                        description: string;
                                    };
                                    email: {
                                        description: string;
                                    };
                                    firstName: {
                                        description: string;
                                    };
                                    gender: {
                                        description: string;
                                    };
                                    id: {
                                        description: string;
                                    };
                                    lastName: {
                                        description: string;
                                    };
                                    link: {
                                        description: string;
                                    };
                                    name: {
                                        description: string;
                                    };
                                };
                            };
                        };
                        github: {
                            callbackUrl: FormAttributes;
                            clientId: FormAttributes;
                            clientSecret: FormAttributes;
                            scopes: {
                                heading: string;
                                hint: string;
                                list: {
                                    email: {
                                        description: string;
                                    };
                                    profile: {
                                        description: string;
                                    };
                                };
                            };
                        };
                        google: {
                            callbackUrl: FormAttributes;
                            clientId: FormAttributes;
                            clientSecret: FormAttributes;
                            enableGoogleOneTap: FormAttributes;
                            AdditionalQueryParameters: FormAttributes;
                            scopes: {
                                heading: string;
                                hint: string;
                                list: {
                                    email: {
                                        description: string;
                                    };
                                    openid: {
                                        description: string;
                                    };
                                    profile: {
                                        description: string;
                                    };
                                };
                            };
                        };
                        microsoft: {
                            callbackUrl: FormAttributes;
                            clientId: FormAttributes;
                            clientSecret: FormAttributes;
                            commonAuthQueryParams: FormAttributes;
                            scopes: {
                                ariaLabel: string;
                                heading: string;
                                hint: string;
                                label: string;
                                list: {
                                    email: {
                                        description: string;
                                    };
                                    openid: {
                                        description: string;
                                    };
                                    profile: {
                                        description: string;
                                    };
                                };
                                placeholder: string;
                            };
                        };
                        hypr: {
                            appId: FormAttributes;
                            apiToken: FormAttributes;
                            baseUrl: FormAttributes;
                        };
                        saml: {
                            AuthRedirectUrl: FormAttributes;
                            SPEntityId: FormAttributes;
                            SSOUrl: FormAttributes;
                            IdPEntityId: FormAttributes;
                            NameIDType: FormAttributes;
                            RequestMethod: FormAttributes;
                            IsSLORequestAccepted: FormAttributes;
                            IsLogoutEnabled: FormAttributes;
                            LogoutReqUrl: FormAttributes;
                            IsAuthnRespSigned: FormAttributes;
                            IsLogoutReqSigned: FormAttributes;
                            ISAuthnReqSigned: FormAttributes;
                            SignatureAlgorithm: FormAttributes;
                            DigestAlgorithm: FormAttributes;
                            IncludeProtocolBinding: FormAttributes;
                            IsUserIdInClaims: FormAttributes;
                            commonAuthQueryParams: FormAttributes;

                            isAssertionSigned: FormAttributes;
                            includeCert: FormAttributes;
                            includeNameIDPolicy: FormAttributes;
                            isEnableAssertionEncryption: FormAttributes;

                            authenticationContextClass: FormAttributes;
                            customAuthenticationContextClass: FormAttributes;
                            attributeConsumingServiceIndex: FormAttributes;

                            isArtifactBindingEnabled: FormAttributes;
                            artifactResolveEndpointUrl: FormAttributes;
                            isArtifactResolveReqSigned: FormAttributes;
                            isArtifactResponseSigned: FormAttributes;
                            authContextComparisonLevel: FormAttributes;
                        };
                    };
                    outboundConnectorAccordion?: {
                        default: {
                            0: string;
                            1: string;
                        };
                        enable: {
                            0: string;
                            1: string;
                        };
                    };
                    common?: {
                        requiredErrorMessage: string;
                        invalidURLErrorMessage: string;
                        invalidQueryParamErrorMessage: string;
                        invalidScopesErrorMessage: string;
                        customProperties: string;
                    };
                    generalDetails?: {
                        name: FormAttributes;
                        issuer: FormAttributes;
                        alias: FormAttributes;
                        description: FormAttributes;
                        image: FormAttributes;
                    };
                    jitProvisioning?: {
                        enableJITProvisioning: FormAttributes;
                        provisioningUserStoreDomain: FormAttributes;
                        provisioningScheme: {
                            hint: string;
                            label: string;
                            children: {
                                0: string;
                                1: string;
                                2: string;
                                3: string;
                            };
                        };
                        associateLocalUser: FormAttributes;
                    };
                    roleMapping?: {
                        heading: string;
                        keyName: string;
                        valueName: string;
                        validation: {
                            keyRequiredMessage: string;
                            valueRequiredErrorMessage: string;
                            duplicateKeyErrorMsg: string;
                        };
                        hint: string;
                    };
                    uriAttributeSettings?: {
                        subject: {
                            heading: string;
                            hint: string;
                            placeHolder: string;
                            label: string;
                            validation: {
                                empty: string;
                            };
                        };
                        group: {
                            heading: string;
                            hint: string;
                            mappedRolesAbsentMessage: string;
                            mappedRolesPresentMessage: string;
                            messageOIDC: string;
                            messageSAML: string;
                            placeHolder: string;
                            roleMappingDisabledMessage: string;
                            label: string;
                            validation: {
                                empty: string;
                            };
                        };
                    };
                    outboundProvisioningRoles?: {
                        heading: string;
                        hint: string;
                        placeHolder: string;
                        label: string;
                        popup: {
                            content: string;
                        };
                    };
                    certificateSection?: {
                        certificateEditSwitch: {
                            jwks: string;
                            pem: string;
                        };
                        noCertificateAlert: string;
                    };
                };
                helpPanel?: HelpPanelInterface;
                templates?: {
                    manualSetup?: {
                        heading: string;
                        subHeading: string;
                    };
                    quickSetup?: {
                        heading: string;
                        subHeading: string;
                    };
                    apple: {
                        wizardHelp: {
                            clientId: {
                                description: string;
                                heading: string;
                            };
                            heading: string;
                            keyId: {
                                description: string;
                                heading: string;
                            };
                            name: {
                                connectionDescription: string;
                                idpDescription: string;
                                heading: string;
                            };
                            preRequisites: {
                                configureAppleSignIn: string;
                                configureReturnURL: string;
                                configureWebDomain: string;
                                getCredentials: string;
                                heading: string;
                            };
                            privateKey: {
                                description: string;
                                heading: string;
                            };
                            subHeading: string;
                            teamId: {
                                description: string;
                                heading: string;
                            };
                        };
                    };
                    expert: {
                        wizardHelp: {
                            heading: string;
                            description: {
                                connectionDescription: string;
                                heading: string;
                                idpDescription: string;
                            };
                            name: {
                                connectionDescription: string;
                                heading: string;
                                idpDescription: string;
                            };
                            subHeading: string;
                        };
                    };
                    facebook?: {
                        wizardHelp: {
                            clientId: {
                                description: string;
                                heading: string;
                            };
                            clientSecret: {
                                description: string;
                                heading: string;
                            };
                            heading: string;
                            name: {
                                idpDescription: string;
                                connectionDescription: string;
                                heading: string;
                            };
                            preRequisites: {
                                configureOAuthApps: string;
                                configureRedirectURL: string;
                                configureSiteURL: string;
                                getCredentials: string;
                                heading: string;
                            };
                            subHeading: string;
                        };
                    };
                    github?: {
                        wizardHelp: {
                            heading: string;
                            subHeading: string;
                            clientId: {
                                description: string;
                                heading: string;
                            };
                            clientSecret: {
                                description: string;
                                heading: string;
                            };
                            name: {
                                idpDescription: string;
                                connectionDescription: string;
                                heading: string;
                            };
                            preRequisites: {
                                configureOAuthApps: string;
                                configureHomePageURL: string;
                                configureRedirectURL: string;
                                heading: string;
                                getCredentials: string;
                            };
                        };
                    };
                    google?: {
                        wizardHelp: {
                            clientId: {
                                description: string;
                                heading: string;
                            };
                            clientSecret: {
                                description: string;
                                heading: string;
                            };
                            heading: string;
                            name: {
                                idpDescription: string;
                                connectionDescription: string;
                                heading: string;
                            };
                            preRequisites: {
                                configureOAuthApps: string;
                                configureRedirectURL: string;
                                getCredentials: string;
                                heading: string;
                            };
                            subHeading: string;
                        };
                    };
                    organizationIDP?: {
                        wizardHelp: {
                            name: {
                                description: string;
                                heading: string;
                            };
                            description: {
                                description: string;
                                heading: string;
                                example: string;
                            };
                        };
                    };
                    microsoft?: {
                        wizardHelp: {
                            clientId: {
                                description: string;
                                heading: string;
                            };
                            clientSecret: {
                                description: string;
                                heading: string;
                            };
                            heading: string;
                            name: {
                                idpDescription: string;
                                connectionDescription: string;
                                heading: string;
                            };
                            preRequisites: {
                                configureOAuthApps: string;
                                configureRedirectURL: string;
                                getCredentials: string;
                                heading: string;
                            };
                            subHeading: string;
                        };
                    };
                    hypr?: {
                        wizardHelp: {
                            apiToken: {
                                description: string;
                                heading: string;
                            };
                            appId: {
                                description: string;
                                heading: string;
                            };
                            baseUrl: {
                                description: string;
                                heading: string;
                            };
                            heading: string;
                            name: {
                                idpDescription: string;
                                connectionDescription: string;
                                heading: string;
                            };
                            preRequisites: {
                                rpDescription: string;
                                tokenDescription: string;
                                heading: string;
                            };
                        };
                    };
                    enterprise?: {
                        addWizard?: {
                            title: string;
                            subtitle: string;
                        };
                        saml?: {
                            preRequisites: {
                                configureIdp: string;
                                configureRedirectURL: string;
                                heading: string;
                                hint: string;
                            };
                        };
                        validation: {
                            name: string;
                            invalidName: string;
                        };
                    };
                    trustedTokenIssuer?: {
                        addWizard?: {
                            title: string;
                            subtitle: string;
                        };
                        forms?: {
                            steps?: {
                                general?: string;
                                certificate?: string;
                            };
                            name?: {
                                label?: string;
                                placeholder?: string;
                            };
                            issuer?: {
                                label?: string;
                                placeholder?: string;
                                hint?: string;
                                validation?: {
                                    notValid: string;
                                };
                            };
                            alias?: {
                                label?: string;
                                placeholder?: string;
                                hint?: string;
                                validation?: {
                                    notValid: string;
                                };
                            };
                            certificateType?: {
                                label?: string;
                                requiredCertificate?: string;
                            };
                            jwksUrl?: {
                                optionLabel?: string;
                                placeholder?: string;
                                label?: string;
                                hint?: string;
                                validation?: {
                                    notValid: string;
                                };
                            };
                            pem?: {
                                optionLabel?: string;
                                hint?: string;
                                uploadCertificateButtonLabel?: string;
                                dropzoneText?: string;
                                pasteAreaPlaceholderText?: string;
                            };
                        };
                    };
                };
                list?: {
                    actions: string;
                    name: string;
                };
                modals?: {
                    addAuthenticator: {
                        title: string;
                        subTitle: string;
                    };
                    addCertificate: {
                        title: string;
                        subTitle: string;
                    };
                    addProvisioningConnector: {
                        title: string;
                        subTitle: string;
                    };
                    attributeSelection: {
                        title: string;
                        subTitle: string;
                        content: {
                            searchPlaceholder: string;
                        };
                    };
                };
                notifications?: {
                    addFederatedAuthenticator: Notification;
                    addIDP: Notification;
                    changeCertType: {
                        pem: {
                            description: string;
                            message: string;
                        };
                        jwks: {
                            description: string;
                            message: string;
                        };
                    };
                    deleteCertificate: Notification;
                    deleteIDP: Notification;
                    deleteIDPWithConnectedApps: Notification;
                    deleteConnection: Notification;
                    disableAuthenticator: Notification;
                    disableIDPWithConnectedApps: Notification;
                    disableOutboundProvisioningConnector: Notification;
                    duplicateCertificateUpload: Notification;
                    getIDP: Notification;
                    getIDPList: Notification;
                    getIDPTemplate: Notification;
                    getIDPTemplateList: Notification;
                    getFederatedAuthenticator: Notification;
                    getFederatedAuthenticatorsList: Notification;
                    getFederatedAuthenticatorMetadata: Notification;
                    getConnectionDetails: Notification;
                    getOutboundProvisioningConnector: Notification;
                    getOutboundProvisioningConnectorsList: Notification;
                    getOutboundProvisioningConnectorMetadata: Notification;
                    getAllLocalClaims: Notification;
                    getRolesList: Notification;
                    submitAttributeSettings: Notification;
                    deleteDefaultAuthenticator: Notification;
                    deleteDefaultConnector: Notification;
                    updateAttributes: Notification;
                    updateClaimsConfigs: Notification;
                    updateFederatedAuthenticator: Notification;
                    updateFederatedAuthenticators: Notification;
                    updateEmailOTPAuthenticator: Notification;
                    updateSMSOTPAuthenticator: Notification;
                    updateGenericAuthenticator: Notification;
                    updateIDP: Notification;
                    updateIDPCertificate: Notification;
                    updateIDPRoleMappings: Notification;
                    updateJITProvisioning: Notification;
                    updateOutboundProvisioningConnectors: Notification;
                    updateOutboundProvisioningConnector: Notification;
                    apiLimitReachedError: {
                        error: {
                            description: string;
                            message: string;
                        };
                    };
                };
                popups?: {
                    appStatus: {
                        enabled: Popup;
                        disabled: Popup;
                    };
                };
                placeHolders?: {
                    emptyCertificateList: Placeholder;
                    emptyIDPList: Placeholder;
                    emptyIDPSearchResults: Placeholder;
                    emptyAuthenticatorList: Placeholder;
                    emptyConnectionTypeList: {
                        subtitles: {
                            0: string;
                            1: string;
                        };
                        title: string;
                    };
                    emptyConnectorList: Placeholder;
                    noAttributes: Placeholder;
                };
                wizards?: {
                    addAuthenticator: {
                        header: string;
                        steps: {
                            authenticatorSelection: {
                                title: string;
                                quickSetup: {
                                    title: string;
                                    subTitle: string;
                                };
                                manualSetup: {
                                    title: string;
                                    subTitle: string;
                                };
                            };
                            authenticatorConfiguration: {
                                title: string;
                            };
                            authenticatorSettings: {
                                emptyPlaceholder: {
                                    subtitles: [string, string];
                                    title: string;
                                };
                            };
                            summary: {
                                title: string;
                            };
                        };
                    };
                    addIDP: {
                        header: string;
                        steps: {
                            generalSettings: {
                                title: string;
                            };
                            authenticatorConfiguration: {
                                title: string;
                            };
                            provisioningConfiguration: {
                                title: string;
                            };
                            summary: {
                                title: string;
                            };
                        };
                    };
                    addProvisioningConnector: {
                        header: string;
                        steps: {
                            connectorSelection: {
                                title: string;
                                defaultSetup: {
                                    title: string;
                                    subTitle: string;
                                };
                            };
                            connectorConfiguration: {
                                title: string;
                            };
                            summary: {
                                title: string;
                            };
                        };
                    };
                    buttons: {
                        next: string;
                        finish: string;
                        previous: string;
                    };
                };
            };
            idp: {
                advancedSearch: {
                    form: {
                        inputs: {
                            filterAttribute: {
                                placeholder: string;
                            };
                            filterCondition: {
                                placeholder: string;
                            };
                            filterValue: {
                                placeholder: string;
                            };
                        };
                    };
                    placeholder: string;
                };
                buttons: {
                    addIDP: string;
                    addAuthenticator: string;
                    addConnector: string;
                    addAttribute: string;
                    addCertificate: string;
                };
                confirmations: {
                    deleteIDP: Confirmation;
                    deleteIDPWithConnectedApps: Confirmation;
                    deleteAuthenticator: Confirmation;
                    deleteConnector: Confirmation;
                };
                connectedApps: {
                    action: string;
                    header: string;
                    subHeader: string;
                    placeholders: {
                        search: string;
                        emptyList: string;
                    };
                    applicationEdit: {
                        back: string;
                    };
                    genericError: {
                        description: string;
                        message: string;
                    };
                };
                dangerZoneGroup: {
                    header: string;
                    disableIDP: DangerZone;
                    deleteIDP: DangerZone;
                };
                forms: {
                    advancedConfigs: {
                        federationHub: FormAttributes;
                        homeRealmIdentifier: FormAttributes;
                        alias: FormAttributes;
                        certificateType: {
                            label: string;
                            hint: string;
                            certificatePEM: FormAttributes;
                            certificateJWKS: FormAttributes;
                        };
                        implicitAssociation: {
                            enable: {
                                label: string;
                                hint: string;
                            };
                            primaryAttribute: {
                                label: string;
                                hint: string;
                            };
                            secondaryAttribute: {
                                label: string;
                                hint: string;
                            };
                            warning: string;
                        };
                    };
                    attributeSettings: {
                        attributeMapping: {
                            attributeColumnHeader: string;
                            attributeMapColumnHeader: string;
                            attributeMapInputPlaceholderPrefix: string;
                            componentHeading: string;
                            hint: string;
                            placeHolder: {
                                title: string;
                                subtitle: string;
                                action: string;
                            };
                            attributeMapTable: {
                                mappedAttributeColumnHeader: string;
                                externalAttributeColumnHeader: string;
                            };
                            heading: string;
                            subheading: string;
                            search: {
                                placeHolder: string;
                            };
                            attributeDropdown: {
                                label: string;
                                placeHolder: string;
                                noResultsMessage: string;
                            };
                            externalAttributeInput: {
                                label: string;
                                placeHolder: string;
                                existingErrorMessage: string;
                            };
                            addAttributeButtonLabel: string;
                            modal: {
                                header: string;
                                placeholder: {
                                    title: string;
                                    subtitle: string;
                                };
                            };
                        };
                        attributeProvisioning: {
                            attributeColumnHeader: {
                                0: string;
                                1: string;
                            };
                            attributeMapColumnHeader: string;
                            attributeMapInputPlaceholderPrefix: string;
                            componentHeading: string;
                            hint: string;
                        };
                        attributeListItem: {
                            validation: {
                                empty: string;
                            };
                        };
                        attributeSelection: {
                            searchAttributes: {
                                placeHolder: string;
                            };
                        };
                    };
                    authenticatorAccordion: {
                        default: {
                            0: string;
                            1: string;
                        };
                        enable: {
                            0: string;
                            1: string;
                        };
                    };
                    outboundConnectorAccordion: {
                        default: {
                            0: string;
                            1: string;
                        };
                        enable: {
                            0: string;
                            1: string;
                        };
                    };
                    common: {
                        requiredErrorMessage: string;
                        invalidURLErrorMessage: string;
                        invalidQueryParamErrorMessage: string;
                        customProperties: string;
                        internetResolvableErrorMessage: string;
                    };
                    generalDetails: {
                        name: FormAttributes;
                        description: FormAttributes;
                        image: FormAttributes;
                    };
                    jitProvisioning: {
                        enableJITProvisioning: FormAttributes;
                        provisioningUserStoreDomain: FormAttributes;
                        provisioningScheme: {
                            hint: string;
                            label: string;
                            children: {
                                0: string;
                                1: string;
                                2: string;
                                3: string;
                            };
                        };
                    };
                    roleMapping: {
                        heading: string;
                        keyName: string;
                        valueName: string;
                        validation: {
                            keyRequiredMessage: string;
                            valueRequiredErrorMessage: string;
                            duplicateKeyErrorMsg: string;
                        };
                        hint: string;
                    };
                    uriAttributeSettings: {
                        subject: {
                            heading: string;
                            hint: string;
                            placeHolder: string;
                            label: string;
                            validation: {
                                empty: string;
                            };
                        };
                        role: {
                            heading: string;
                            hint: string;
                            placeHolder: string;
                            label: string;
                            validation: {
                                empty: string;
                            };
                        };
                    };
                    outboundProvisioningRoles: {
                        heading: string;
                        hint: string;
                        placeHolder: string;
                        label: string;
                        popup: {
                            content: string;
                        };
                    };
                    outboundProvisioningTitle: string;
                };
                helpPanel: HelpPanelInterface;
                templates: {
                    manualSetup: {
                        heading: string;
                        subHeading: string;
                    };
                    quickSetup: {
                        heading: string;
                        subHeading: string;
                    };
                };
                list: {
                    actions: string;
                    name: string;
                };
                modals: {
                    addAuthenticator: {
                        title: string;
                        subTitle: string;
                    };
                    addCertificate: {
                        title: string;
                        subTitle: string;
                    };
                    addProvisioningConnector: {
                        title: string;
                        subTitle: string;
                    };
                    attributeSelection: {
                        title: string;
                        subTitle: string;
                        content: {
                            searchPlaceholder: string;
                        };
                    };
                };
                notifications: {
                    addFederatedAuthenticator: Notification;
                    addIDP: Notification;
                    apiLimitReachedError: Notification;
                    changeCertType: {
                        pem: {
                            description: string;
                            message: string;
                        };
                        jwks: {
                            description: string;
                            message: string;
                        };
                    };
                    deleteCertificate: Notification;
                    deleteIDP: Notification;
                    disableAuthenticator: Notification;
                    disableOutboundProvisioningConnector: Notification;
                    duplicateCertificateUpload: Notification;
                    getIDP: Notification;
                    getIDPList: Notification;
                    getIDPTemplate: Notification;
                    getIDPTemplateList: Notification;
                    getFederatedAuthenticator: Notification;
                    getFederatedAuthenticatorsList: Notification;
                    getFederatedAuthenticatorMetadata: Notification;
                    getOutboundProvisioningConnector: Notification;
                    getOutboundProvisioningConnectorsList: Notification;
                    getOutboundProvisioningConnectorMetadata: Notification;
                    getAllLocalClaims: Notification;
                    getRolesList: Notification;
                    submitAttributeSettings: Notification;
                    tierLimitReachedError: {
                        emptyPlaceholder: Placeholder;
                        heading: string;
                    };
                    deleteDefaultAuthenticator: Notification;
                    deleteDefaultConnector: Notification;
                    updateClaimsConfigs: Notification;
                    updateFederatedAuthenticator: Notification;
                    updateFederatedAuthenticators: Notification;
                    updateIDP: Notification;
                    updateIDPCertificate: Notification;
                    updateIDPRoleMappings: Notification;
                    updateJITProvisioning: Notification;
                    updateOutboundProvisioningConnectors: Notification;
                    updateOutboundProvisioningConnector: Notification;
                };
                placeHolders: {
                    emptyCertificateList: Placeholder;
                    emptyIDPList: Placeholder;
                    emptyIDPSearchResults: Placeholder;
                    emptyAuthenticatorList: Placeholder;
                    emptyConnectorList: Placeholder;
                    noAttributes: Placeholder;
                };
                wizards: {
                    addAuthenticator: {
                        header: string;
                        steps: {
                            authenticatorSelection: {
                                title: string;
                                quickSetup: {
                                    title: string;
                                    subTitle: string;
                                };
                                manualSetup: {
                                    title: string;
                                    subTitle: string;
                                };
                            };
                            authenticatorConfiguration: {
                                title: string;
                            };
                            summary: {
                                title: string;
                            };
                        };
                    };
                    addIDP: {
                        header: string;
                        steps: {
                            generalSettings: {
                                title: string;
                            };
                            authenticatorConfiguration: {
                                title: string;
                            };
                            provisioningConfiguration: {
                                title: string;
                            };
                            summary: {
                                title: string;
                            };
                        };
                    };
                    addProvisioningConnector: {
                        header: string;
                        steps: {
                            connectorSelection: {
                                title: string;
                                defaultSetup: {
                                    title: string;
                                    subTitle: string;
                                };
                            };
                            connectorConfiguration: {
                                title: string;
                            };
                            summary: {
                                title: string;
                            };
                        };
                    };
                    buttons: {
                        next: string;
                        finish: string;
                        previous: string;
                    };
                };
            };
        };
        pages: {
            applicationTemplate: EditPage;
            applications: Page;
            applicationsEdit: EditPage;
            authenticationProvider?: Page;
            authenticationProviderTemplate: {
                title: string;
                subTitle: string;
                backButton: string;
                disabledHint: {
                    apple: string;
                };
                search: {
                    placeholder: string;
                };
                supportServices: {
                    authenticationDisplayName: string;
                    provisioningDisplayName: string;
                };
            };
            idp: Page;
            idpTemplate: {
                title: string;
                subTitle: string;
                backButton: string;
                supportServices: {
                    authenticationDisplayName: string;
                    provisioningDisplayName: string;
                };
            };
            idvp: Page;
            idvpTemplate: {
                title: string;
                subTitle: string;
                backButton: string;
                search: {
                    placeholder: string;
                };
            };
            overview: Page;
        };
        placeholders: {
            emptySearchResult: Placeholder;
            underConstruction: Placeholder;
        };
    };
    manage: {
        features: {
            users: {
                addUserType: {
                    createUser: {
                        title: string;
                        description: string;
                    };
                    inviteParentUser: {
                        title: string;
                        description: string;
                    };
                };
                consumerUsers: {
                    fields: {
                        username: {
                            label: string;
                            placeholder: string;
                            validations: {
                                empty: string;
                                invalid: string;
                                invalidCharacters: string;
                                regExViolation: string;
                            };
                        };
                    };
                };
                guestUsers: {
                    fields: {
                        username: {
                            label: string;
                            placeholder: string;
                            validations: {
                                empty: string;
                                invalid: string;
                                invalidCharacters: string;
                                regExViolation: string;
                            };
                        };
                    };
                };
                confirmations: {
                    terminateAllSessions: Confirmation;
                    terminateSession: Confirmation;
                    addMultipleUser: Confirmation;
                };
                editUser: {
                    tab: {
                        menuItems: {
                            0: string;
                            1: string;
                            2: string;
                            3: string;
                        };
                    };
                    placeholders: {
                        undefinedUser: Placeholder;
                    };
                };
                userSessions: {
                    components: {
                        sessionDetails: {
                            actions: {
                                terminateAllSessions: string;
                                terminateSession: string;
                            };
                            labels: {
                                browser: string;
                                deviceModel: string;
                                ip: string;
                                lastAccessed: string;
                                loggedInAs: string;
                                loginTime: string;
                                os: string;
                                recentActivity: string;
                                activeApplication: string;
                            };
                        };
                    };
                    dangerZones: {
                        terminate: DangerZone;
                    };
                    notifications: {
                        getUserSessions: Notification;
                        terminateAllUserSessions: Notification;
                        terminateUserSession: Notification;
                        getAdminUser: Notification;
                    };
                    placeholders: {
                        emptyListPlaceholder: Placeholder;
                    };
                };
                advancedSearch: {
                    form: {
                        dropdown: {
                            filterAttributeOptions: {
                                username: string;
                                email: string;
                            };
                        };
                        inputs: {
                            filterAttribute: {
                                placeholder: string;
                            };
                            filterCondition: {
                                placeholder: string;
                            };
                            filterValue: {
                                placeholder: string;
                            };
                        };
                    };
                    placeholder: string;
                };
                all: {
                    heading: string;
                    subHeading: string;
                };
                buttons: {
                    addNewUserBtn: string;
                    assignUserRoleBtn: string;
                    metaColumnBtn: string;
                };
                addUserDropDown: {
                    addNewUser: string;
                    bulkImport: string;
                };
                forms: {
                    validation: {
                        formatError: string;
                        dateFormatError: string;
                        mobileFormatError: string;
                        futureDateError: string;
                    };
                };
                list: {
                    columns: {
                        actions: string;
                        name: string;
                    };
                };
                notifications: {
                    addUser: Notification;
                    addUserPendingApproval: Notification;
                    bulkImportUser: {
                        validation: {
                            emptyRowError: NotificationItem;
                            columnMismatchError: NotificationItem;
                            emptyHeaderError: NotificationItem;
                            missingRequiredHeaderError: NotificationItem;
                            blockedHeaderError: NotificationItem;
                            duplicateHeaderError: NotificationItem;
                            invalidHeaderError: NotificationItem;
                            emptyDataField: NotificationItem;
                            invalidRole: NotificationItem;
                            invalidGroup: NotificationItem;
                        };
                        submit: Notification;
                        timeOut: NotificationItem;
                    };
                    deleteUser: Notification;
                    fetchUsers: Notification;
                    getAdminRole: Notification;
                    revokeAdmin: Notification;
                };
                placeholders: {
                    emptyList: Placeholder;
                    userstoreError: Placeholder;
                };
                usersList: {
                    list: {
                        emptyResultPlaceholder: {
                            addButton: string;
                            emptyUsers: string;
                            subTitle: {
                                0: string;
                                1: string;
                                2: string;
                            };
                            title: string;
                        };
                        iconPopups: {
                            delete: string;
                            edit: string;
                        };
                    };
                    metaOptions: {
                        heading: string;
                        columns: {
                            name: string;
                            emails: string;
                            id: string;
                            userName: string;
                            lastModified: string;
                        };
                    };
                    search: {
                        emptyResultPlaceholder: {
                            clearButton: string;
                            subTitle: {
                                0: string;
                                1: string;
                            };
                            title: string;
                        };
                    };
                };
                userstores: {
                    userstoreOptions: {
                        all: string;
                        primary: string;
                    };
                };
            };

            certificates: {
                keystore: {
                    advancedSearch: {
                        form: {
                            inputs: {
                                filterAttribute: {
                                    placeholder: string;
                                };
                                filterCondition: {
                                    placeholder: string;
                                };
                                filterValue: {
                                    placeholder: string;
                                };
                            };
                        };
                        error: string;
                        placeholder: string;
                    };
                    attributes: {
                        alias: string;
                    };
                    list: {
                        columns: {
                            actions: string;
                            name: string;
                        };
                    };
                    notifications: {
                        addCertificate: Notification;
                        getCertificates: Notification;
                        getAlias: Notification;
                        getPublicCertificate: Notification;
                        getCertificate: Notification;
                        deleteCertificate: Notification;
                        download: Notification;
                    };
                    certificateModalHeader: string;
                    placeholders: {
                        emptySearch: {
                            action: string;
                            title: string;
                            subtitle: string;
                        };
                        emptyList: {
                            action: string;
                            title: string;
                            subtitle: string;
                        };
                    };
                    confirmation: {
                        hint: string;
                        primaryAction: string;
                        header: string;
                        content: string;
                        message: string;
                        tenantContent: string;
                    };
                    pageLayout: {
                        title: string;
                        description: string;
                        primaryAction: string;
                    };
                    summary: {
                        sn: string;
                        validFrom: string;
                        validTill: string;
                        issuerDN: string;
                        subjectDN: string;
                        version: string;
                    };
                    wizard: {
                        panes: {
                            upload: string;
                            paste: string;
                        };
                        steps: {
                            upload: string;
                            summary: string;
                        };
                        header: string;
                        dropZone: {
                            description: string;
                            action: string;
                        };
                        pastePlaceholder: string;
                    };
                    forms: {
                        alias: FormField;
                    };
                    errorEmpty: string;
                    errorCertificate: string;
                };
                truststore: {
                    advancedSearch: {
                        form: {
                            inputs: {
                                filterAttribute: {
                                    placeholder: string;
                                };
                                filterCondition: {
                                    placeholder: string;
                                };
                                filterValue: {
                                    placeholder: string;
                                };
                            };
                        };
                        placeholder: string;
                    };
                };
            };

            roles: {
                addRoleWizard: {
                    buttons: {
                        finish: string;
                        next: string;
                        previous: string;
                    };
                    forms: {
                        roleBasicDetails: {
                            domain: {
                                label: {
                                    role: string;
                                    group: string;
                                };
                                placeholder: string;
                                validation: {
                                    empty: {
                                        role: string;
                                        group: string;
                                    };
                                };
                            };
                            roleName: {
                                hint: string;
                                label: string;
                                placeholder: string;
                                validations: {
                                    duplicate: string;
                                    duplicateInAudience: string;
                                    empty: string;
                                    invalid: string;
                                };
                            };
                            roleAudience: FormAttributes;
                            assignedApplication: FormAttributes;
                            notes: {
                                orgNote: string;
                                appNote: string;
                                cannotCreateRole: string;
                            };
                        };
                        rolePermission: {
                            apiResource: {
                                label: string;
                                placeholder: string;
                                hint: {
                                    empty: string;
                                };
                            };
                            permissions: {
                                label: string;
                                placeholder: string;
                                tooltips: {
                                    noScopes: string;
                                    selectAllScopes: string;
                                    removeAPIResource: string;
                                };
                                validation: {
                                    empty: string;
                                };
                                permissionsLabel: string;
                            };
                            notes: {
                                applicationRoles: string;
                            };
                            notifications: {
                                fetchAPIResourceError: Notification;
                            };
                        };
                    };
                    heading: string;
                    permissions: {
                        buttons: {
                            collapseAll: string;
                            expandAll: string;
                            update: string;
                        };
                    };
                    subHeading: string;
                    back: string;
                    summary: {
                        labels: {
                            domain: {
                                role: string;
                                group: string;
                            };
                            permissions: string;
                            roleName: string;
                            roles: string;
                            users: string;
                            groups: string;
                        };
                    };
                    users: {
                        assignUserModal: {
                            heading: string;
                            hint: string;
                            subHeading: string;
                            list: {
                                searchPlaceholder: string;
                                searchByEmailPlaceholder: string;
                                listHeader: string;
                            };
                        };
                    };
                    wizardSteps: {
                        0: string;
                        1: string;
                        2: string;
                        3: string;
                        4: string;
                        5: string;
                    };
                };
                advancedSearch: {
                    form: {
                        inputs: {
                            filterAttribute: {
                                placeholder: string;
                            };
                            filterCondition: {
                                placeholder: string;
                            };
                            filterValue: {
                                placeholder: string;
                            };
                        };
                    };
                    placeholder: string;
                };
                edit: {
                    placeholders: {
                        errorPlaceHolder: Placeholder;
                    };
                    basics: {
                        buttons: {
                            update: string;
                        };
                        confirmation: Confirmation;
                        dangerZone: DangerZone;
                        fields: {
                            roleName: {
                                name: string;
                                required: string;
                                placeholder: string;
                            };
                        };
                    };
                    groups: {
                        addGroupsModal: {
                            heading: string;
                            subHeading: string;
                        };
                        placeholders: {
                            emptyPlaceholder: Placeholder;
                            errorPlaceholder: Placeholder;
                        };
                        notifications: {
                            error: NotificationItem;
                            success: NotificationItem;
                            genericError: NotificationItem;
                            fetchError: NotificationItem;
                        };
                        heading: string;
                        localGroupsHeading: string;
                        externalGroupsHeading: string;
                        subHeading: string;
                        actions: {
                            search: {
                                placeholder: string;
                            };
                            assign: {
                                placeholder: string;
                            };
                            remove: {
                                label: string;
                                placeholder: string;
                            };
                        };
                    };
                    menuItems: {
                        basic: string;
                        connectedApps: string;
                        permissions: string;
                        groups: string;
                        users: string;
                        roles: string;
                    };
                    users: {
                        heading: string;
                        subHeading: string;
                        placeholders: {
                            emptyPlaceholder: Placeholder;
                            errorPlaceholder: Placeholder;
                        };
                        notifications: {
                            error: NotificationItem;
                            success: NotificationItem;
                            genericError: NotificationItem;
                            fetchError: NotificationItem;
                        };
                        list: {
                            emptyPlaceholder: Placeholder;
                            user: string;
                            organization: string;
                        };
                        actions: {
                            search: {
                                placeholder: string;
                            };
                            assign: {
                                placeholder: string;
                            };
                            remove: {
                                label: string;
                                placeholder: string;
                            };
                        };
                    };
                    permissions: {
                        heading: string;
                        subHeading: string;
                        readOnlySubHeading: string;
                        removedPermissions: string;
                    };
                };
                list: {
                    buttons: {
                        addButton: string;
                        filterDropdown: string;
                    };
                    columns: {
                        actions: string;
                        lastModified: string;
                        name: string;
                        managedByOrg: {
                            label: string;
                            header: string;
                        };
                        managedByApp: {
                            label: string;
                            header: string;
                        };
                        audience: string;
                    };
                    confirmations: {
                        deleteItem: Confirmation;
                        deleteItemError: InfoModal;
                    };
                    emptyPlaceholders: {
                        search: Placeholder;
                        emptyRoleList: Placeholder & {
                            emptyRoles: string;
                        };
                    };
                    popups: {
                        delete: string;
                        edit: string;
                    };
                    filterOptions: {
                        all: string;
                        applicationRoles: string;
                        organizationRoles: string;
                    };
                    filterAttirbutes: {
                        name: string;
                        audience: string;
                    };
                };
                readOnlyList: {
                    emptyPlaceholders: {
                        searchAndFilter: Placeholder;
                    };
                };
                notifications: {
                    deleteRole: Notification;
                    fetchRoles: Notification;
                    fetchRole: Notification;
                    updateRole: Notification;
                    createRole: Notification;
                    createPermission: Notification;
                };
            };

            transferList: {
                searchPlaceholder: string;
                list: {
                    headers: {
                        0: string;
                        1: string;
                        2: string;
                    };
                    emptyPlaceholders: {
                        default: string;
                        groups: {
                            unselected: string;
                            selected: string;
                        };
                        roles: {
                            unselected: string;
                            selected: string;
                            common: string;
                        };
                        users: {
                            roles: {
                                unselected: string;
                                selected: string;
                            };
                        };
                    };
                };
            };
        };
        placeholders: {
            emptySearchResult: Placeholder;
            underConstruction: Placeholder;
        };
    };

    access: string;
    actions: string;
    activate: string;
    active: string;
    add: string;
    addKey: string;
    addURL: string;
    all: string;
    applicationName: string;
    applications: string;
    approvalStatus: string;
    approve: string;
    apps: string;
    assignee: string;
    assignees: string;
    authenticator: string;
    authentication: string;
    authenticator_plural: string;
    back: string;
    beta: string;
    browser: string;
    cancel: string;
    challengeQuestionNumber: string;
    change: string;
    chunkLoadErrorMessage: {
        heading: string;
        description: string;
        primaryActionText: string;
    };
    claim: string;
    clear: string;
    clientId: string;
    close: string;
    comingSoon: string;
    completed: string;
    configure: string;
    confirm: string;
    contains: string;
    continue: string;
    copyToClipboard: string;
    createdOn: string;
    create: string;
    dangerZone: string;
    darkMode: string;
    delete: string;
    description: string;
    deviceModel: string;
    docs: string;
    documentation: string;
    done: string;
    download: string;
    drag: string;
    duplicateURLError: string;
    edit: string;
    endsWith: string;
    equals: string;
    exitFullScreen: string;
    explore: string;
    export: string;
    featureAvailable: string;
    filter: string;
    finish: string;
    goBackHome: string;
    goFullScreen: string;
    help: string;
    hide: string;
    hidePassword: string;
    identityProviders: string;
    import: string;
    initiator: string;
    ipAddress: string;
    issuer: string;
    lastAccessed: string;
    lastModified: string;
    lastSeen: string;
    lastUpdatedOn: string;
    learnMore: string;
    lightMode: string;
    loading: string;
    loginTime: string;
    logout: string;
    maximize: string;
    maxValidation: string;
    minimize: string;
    minValidation: string;
    more: string;
    myAccount: string;
    name: string;
    new: string;
    next: string;
    operatingSystem: string;
    operations: string;
    overview: string;
    personalInfo: string;
    pin: string;
    pinned: string;
    preview: string;
    previous: string;
    priority: string;
    privacy: string;
    properties: string;
    ready: string;
    regenerate: string;
    register: string;
    removeAll: string;
    reject: string;
    release: string;
    remove: string;
    reserved: string;
    resetFilters: string;
    retry: string;
    revoke: string;
    revokeAll: string;
    required: string;
    samples: string;
    save: string;
    services: string;
    sdks: string;
    search: string;
    searching: string;
    security: string;
    settings: string;
    setup: string;
    show: string;
    showAll: string;
    showLess: string;
    showMore: string;
    showPassword: string;
    skip: string;
    generatePassword: string;
    startsWith: string;
    step: string;
    submit: string;
    switch: string;
    technologies: string;
    terminate: string;
    terminateAll: string;
    terminateSession: string;
    type: string;
    unpin: string;
    unpinned: string;
    update: string;
    user: string;
    verify: string;
    view: string;
    weakPassword: string;
    good: string;
    strong: string;
    weak: string;
    tooShort: string;
    okay: string;
    enabled: string;
    disabled: string;
    enable: string;
    disable: string;
    networkErrorMessage: {
        heading: string;
        description: string;
        primaryActionText: string;
    };
    noResultsFound: string;
    pressEnterPrompt: string;
}
