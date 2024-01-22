import type ComponentRepresentation from "@keycloak/keycloak-admin-client/lib/defs/componentRepresentation";
import type ComponentTypeRepresentation from "@keycloak/keycloak-admin-client/lib/defs/componentTypeRepresentation";
import { DirectionType } from "@keycloak/keycloak-admin-client/lib/resources/userStorageProvider";
import {
  ActionGroup,
  AlertVariant,
  Button,
  ButtonVariant,
  DropdownItem,
  Form,
  FormGroup,
  PageSection,
  Select,
  SelectOption,
  SelectVariant,
  ValidatedOptions,
} from "@patternfly/react-core";
import { useState } from "react";
import { Controller, FormProvider, useForm, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { HelpItem } from "ui-shared";

import { adminClient } from "../../../admin-client";
import { useAlerts } from "../../../components/alert/Alerts";
import { useConfirmDialog } from "../../../components/confirm-dialog/ConfirmDialog";
import { DynamicComponents } from "../../../components/dynamic/DynamicComponents";
import { FormAccess } from "../../../components/form/FormAccess";
import { KeycloakSpinner } from "../../../components/keycloak-spinner/KeycloakSpinner";
import { KeycloakTextInput } from "../../../components/keycloak-text-input/KeycloakTextInput";
import { ViewHeader } from "../../../components/view-header/ViewHeader";
import { useRealm } from "../../../context/realm-context/RealmContext";
import { convertFormValuesToObject, convertToFormValues } from "../../../util";
import { useFetch } from "../../../utils/useFetch";
import { useParams } from "../../../utils/useParams";
import { toUserFederationLdap } from "../../routes/UserFederationLdap";
import { UserFederationLdapMapperParams } from "../../routes/UserFederationLdapMapper";

export default function LdapMapperDetails() {
  const form = useForm<ComponentRepresentation>();
  const [mapping, setMapping] = useState<ComponentRepresentation>();
  const [components, setComponents] = useState<ComponentTypeRepresentation[]>();

  const { id, mapperId } = useParams<UserFederationLdapMapperParams>();
  const navigate = useNavigate();
  const { realm } = useRealm();
  const { t } = useTranslation();
  const { addAlert, addError } = useAlerts();

  const [isMapperDropdownOpen, setIsMapperDropdownOpen] = useState(false);
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);

  useFetch(
    async () => {
      const components = await adminClient.components.listSubComponents({
        id,
        type: "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
      });
      if (mapperId && mapperId !== "new") {
        const fetchedMapper = await adminClient.components.findOne({
          id: mapperId,
        });
        return { components, fetchedMapper };
      }
      return { components };
    },
    ({ components, fetchedMapper }) => {
      setMapping(fetchedMapper);
      setComponents(components);
      if (mapperId !== "new" && !fetchedMapper) throw new Error(t("notFound"));

      if (fetchedMapper) setupForm(fetchedMapper);
    },
    [],
  );

  const setupForm = (mapper: ComponentRepresentation) => {
    convertToFormValues(mapper, form.setValue);
  };

  const save = async (mapper: ComponentRepresentation) => {
    const component: ComponentRepresentation =
      convertFormValuesToObject(mapper);
    const map = {
      ...component,
      config: Object.entries(component.config || {}).reduce(
        (result, [key, value]) => {
          result[key] = Array.isArray(value) ? value : [value];
          return result;
        },
        {} as Record<string, string | string[]>,
      ),
    };

    try {
      if (mapperId === "new") {
        await adminClient.components.create(map);
        navigate(
          toUserFederationLdap({ realm, id: mapper.parentId!, tab: "mappers" }),
        );
      } else {
        await adminClient.components.update({ id: mapperId }, map);
      }
      setupForm(map as ComponentRepresentation);
      addAlert(
        t(
          mapperId === "new"
            ? "mappingCreatedSuccess"
            : "mappingUpdatedSuccess",
        ),
        AlertVariant.success,
      );
    } catch (error) {
      addError(
        mapperId === "new" ? "mappingCreatedError" : "mappingUpdatedError",
        error,
      );
    }
  };

  const sync = async (direction: DirectionType) => {
    try {
      const result = await adminClient.userStorageProvider.mappersSync({
        parentId: mapping?.parentId || "",
        id: mapperId,
        direction,
      });
      addAlert(
        t("syncLDAPGroupsSuccessful", {
          result: result.status,
        }),
      );
    } catch (error) {
      addError("syncLDAPGroupsError", error);
    }
    refresh();
  };

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: "deleteMappingTitle",
    messageKey: "deleteMappingConfirm",
    continueButtonLabel: "delete",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        await adminClient.components.del({
          id: mapping!.id!,
        });
        addAlert(t("mappingDeletedSuccess"), AlertVariant.success);
        navigate(toUserFederationLdap({ id, realm, tab: "mappers" }));
      } catch (error) {
        addError("mappingDeletedError", error);
      }
    },
  });

  const mapperType = useWatch({
    control: form.control,
    name: "providerId",
  });

  if (!components) {
    return <KeycloakSpinner />;
  }

  const isNew = mapperId === "new";
  const mapper = components.find((c) => c.id === mapperType);
  return (
    <>
      <DeleteConfirm />
      <ViewHeader
        key={key}
        titleKey={mapping ? mapping.name! : t("createNewMapper")}
        dropdownItems={
          isNew
            ? undefined
            : [
                <DropdownItem key="delete" onClick={toggleDeleteDialog}>
                  {t("delete")}
                </DropdownItem>,
                ...(mapper?.metadata.fedToKeycloakSyncSupported
                  ? [
                      <DropdownItem
                        key="fedSync"
                        onClick={() => sync("fedToKeycloak")}
                      >
                        {t(mapper.metadata.fedToKeycloakSyncMessage)}
                      </DropdownItem>,
                    ]
                  : []),
                ...(mapper?.metadata.keycloakToFedSyncSupported
                  ? [
                      <DropdownItem
                        key="ldapSync"
                        onClick={() => {
                          sync("keycloakToFed");
                        }}
                      >
                        {t(mapper.metadata.keycloakToFedSyncMessage)}
                      </DropdownItem>,
                    ]
                  : []),
              ]
        }
      />
      <PageSection variant="light" isFilled>
        <FormAccess role="manage-realm" isHorizontal>
          {!isNew && (
            <FormGroup label={t("id")} fieldId="kc-ldap-mapper-id">
              <KeycloakTextInput
                isDisabled
                id="kc-ldap-mapper-id"
                data-testid="ldap-mapper-id"
                {...form.register("id")}
              />
            </FormGroup>
          )}
          <FormGroup
            label={t("name")}
            labelIcon={
              <HelpItem helpText={t("nameHelp")} fieldLabelId="name" />
            }
            fieldId="kc-ldap-mapper-name"
            isRequired
          >
            <KeycloakTextInput
              isDisabled={!isNew}
              isRequired
              id="kc-ldap-mapper-name"
              data-testid="ldap-mapper-name"
              validated={
                form.formState.errors.name
                  ? ValidatedOptions.error
                  : ValidatedOptions.default
              }
              {...form.register("name", { required: true })}
            />
            <KeycloakTextInput
              hidden
              defaultValue={isNew ? id : mapping ? mapping.parentId : ""}
              id="kc-ldap-parentId"
              data-testid="ldap-mapper-parentId"
              {...form.register("parentId")}
            />
            <KeycloakTextInput
              hidden
              defaultValue="org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
              id="kc-ldap-provider-type"
              data-testid="ldap-mapper-provider-type"
              {...form.register("providerType")}
            />
          </FormGroup>
          {!isNew ? (
            <FormGroup
              label={t("mapperType")}
              labelIcon={
                <HelpItem
                  helpText={
                    mapper?.helpText ? mapper.helpText : t("mapperTypeHelp")
                  }
                  fieldLabelId="mapperType"
                />
              }
              fieldId="kc-ldap-mapper-type"
              isRequired
            >
              <KeycloakTextInput
                isDisabled={!isNew}
                isRequired
                id="kc-ldap-mapper-type"
                data-testid="ldap-mapper-type-fld"
                {...form.register("providerId")}
              />
            </FormGroup>
          ) : (
            <FormGroup
              label={t("mapperType")}
              labelIcon={
                <HelpItem
                  helpText={
                    mapper?.helpText ? mapper.helpText : t("mapperTypeHelp")
                  }
                  fieldLabelId="mapperType"
                />
              }
              fieldId="kc-providerId"
              isRequired
            >
              <Controller
                name="providerId"
                defaultValue=""
                control={form.control}
                data-testid="ldap-mapper-type-select"
                render={({ field }) => (
                  <Select
                    toggleId="kc-providerId"
                    typeAheadAriaLabel={t("mapperType")}
                    required
                    onToggle={() =>
                      setIsMapperDropdownOpen(!isMapperDropdownOpen)
                    }
                    isOpen={isMapperDropdownOpen}
                    onSelect={(_, value) => {
                      field.onChange(value as string);
                      setIsMapperDropdownOpen(false);
                    }}
                    selections={field.value}
                    variant={SelectVariant.typeahead}
                    aria-label={t("selectMapperType")}
                  >
                    {components.map((c) => (
                      <SelectOption key={c.id} value={c.id} />
                    ))}
                  </Select>
                )}
              ></Controller>
            </FormGroup>
          )}
          <FormProvider {...form}>
            {!!mapperType && (
              <DynamicComponents properties={mapper?.properties!} />
            )}
          </FormProvider>
        </FormAccess>

        <Form onSubmit={form.handleSubmit(() => save(form.getValues()))}>
          <ActionGroup>
            <Button
              isDisabled={!form.formState.isDirty}
              variant="primary"
              type="submit"
              data-testid="ldap-mapper-save"
            >
              {t("save")}
            </Button>
            <Button
              variant="link"
              onClick={() =>
                isNew
                  ? navigate(-1)
                  : navigate(
                      `/${realm}/user-federation/ldap/${
                        mapping!.parentId
                      }/mappers`,
                    )
              }
              data-testid="ldap-mapper-cancel"
            >
              {t("cancel")}
            </Button>
          </ActionGroup>
        </Form>
      </PageSection>
    </>
  );
}
