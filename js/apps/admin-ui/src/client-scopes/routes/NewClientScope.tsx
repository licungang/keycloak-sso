import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generateUnencodedPath } from "../../util";
import type { AppRouteObject } from "../../routes";

export type NewClientScopeParams = { realm: string };

const CreateClientScope = lazy(() => import("../CreateClientScope"));

export const NewClientScopeRoute: AppRouteObject = {
  path: "/:realm/client-scopes/new",
  element: <CreateClientScope />,
  breadcrumb: (t) => t("createClientScope"),
  handle: {
    access: "manage-clients",
  },
};

export const toNewClientScope = (
  params: NewClientScopeParams,
): Partial<Path> => ({
  pathname: generateUnencodedPath(NewClientScopeRoute.path, params),
});
