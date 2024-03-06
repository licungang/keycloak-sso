import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import { ActionGroup, Button, PageSection } from "@patternfly/react-core";
import { useEffect, useState } from "react";
import { FormProvider, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";

import { adminClient } from "../../admin-client";
import { useAlerts } from "../../components/alert/Alerts";
import { FormAccess } from "../../components/form/FormAccess";
import { JsonFileUpload } from "../../components/json-file-upload/JsonFileUpload";
import { ViewHeader } from "../../components/view-header/ViewHeader";
import { useRealms } from "../../context/RealmsContext";
import { useWhoAmI } from "../../context/whoami/WhoAmI";
import { toDashboard } from "../../dashboard/routes/Dashboard";
import { convertFormValuesToObject, convertToFormValues } from "../../util";
import { DefaultSwitchControl } from "../../components/SwitchControl";
import { TextControl } from "ui-shared";

export default function NewRealmForm() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { refresh, whoAmI } = useWhoAmI();
  const { refresh: refreshRealms } = useRealms();
  const { addAlert, addError } = useAlerts();
  const [realm, setRealm] = useState<RealmRepresentation>();
  const [defaultValue, setDefaultValue] = useState(true);

  const form = useForm<RealmRepresentation>({
    mode: "onChange",
  });

  const { handleSubmit, setValue } = form;

  useEffect(() => {
    setValue("enabled", defaultValue);
  }, [setValue, defaultValue]);

  const handleFileChange = (obj?: object) => {
    const defaultRealm = { id: "", realm: "", enabled: true };
    convertToFormValues(obj || defaultRealm, setValue);
    setRealm(obj || defaultRealm);
  };

  const save = async (fields: RealmRepresentation) => {
    try {
      await adminClient.realms.create({
        ...realm,
        ...convertFormValuesToObject(fields),
      });
      addAlert(t("saveRealmSuccess"));

      refresh();
      await refreshRealms();
      navigate(toDashboard({ realm: fields.realm }));
    } catch (error) {
      addError("saveRealmError", error);
    }
  };

  return (
    <>
      <ViewHeader titleKey="createRealm" subKey="realmExplain" />
      <PageSection variant="light">
        <FormProvider {...form}>
          <FormAccess
            isHorizontal
            onSubmit={handleSubmit(save)}
            role="view-realm"
            isReadOnly={!whoAmI.canCreateRealm()}
          >
            <JsonFileUpload
              id="kc-realm-filename"
              allowEditingUploadedText
              onChange={handleFileChange}
            />
            <TextControl
              name="realm"
              label={t("realmNameField")}
              rules={{ required: t("required") }}
            />
            <DefaultSwitchControl
              name="enabled"
              label={t("enabled")}
              onChange={(value) => setDefaultValue(value)}
            />
            <ActionGroup>
              <Button variant="primary" type="submit">
                {t("create")}
              </Button>
              <Button variant="link" onClick={() => navigate(-1)}>
                {t("cancel")}
              </Button>
            </ActionGroup>
          </FormAccess>
        </FormProvider>
      </PageSection>
    </>
  );
}
