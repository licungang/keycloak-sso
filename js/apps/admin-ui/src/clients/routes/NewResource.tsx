import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generateUnencodedPath } from "../../util";
import type { AppRouteObject } from "../../routes";

export type NewResourceParams = { realm: string; id: string };

const ResourceDetails = lazy(() => import("../authorization/ResourceDetails"));

export const NewResourceRoute: AppRouteObject = {
  path: "/:realm/clients/:id/authorization/resource/new",
  element: <ResourceDetails />,
  breadcrumb: (t) => t("createResource"),
  handle: {
    access: "view-clients",
  },
};

export const toCreateResource = (params: NewResourceParams): Partial<Path> => ({
  pathname: generateUnencodedPath(NewResourceRoute.path, params),
});
