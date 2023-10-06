import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generateUnencodedPath } from "../../util";
import type { AppRouteObject } from "../../routes";

export type AddExecutorParams = {
  realm: string;
  profileName: string;
};

const ExecutorForm = lazy(() => import("../ExecutorForm"));

export const AddExecutorRoute: AppRouteObject = {
  path: "/:realm/realm-settings/client-policies/:profileName/add-executor",
  element: <ExecutorForm />,
  breadcrumb: (t) => t("addExecutor"),
  handle: {
    access: "manage-realm",
  },
};

export const toAddExecutor = (params: AddExecutorParams): Partial<Path> => ({
  pathname: generateUnencodedPath(AddExecutorRoute.path, params),
});
