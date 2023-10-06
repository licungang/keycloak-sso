import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generateUnencodedPath } from "../../util";
import type { AppRouteObject } from "../../routes";

export type NewPolicyParams = { realm: string; id: string; policyType: string };

const PolicyDetails = lazy(
  () => import("../authorization/policy/PolicyDetails"),
);

export const NewPolicyRoute: AppRouteObject = {
  path: "/:realm/clients/:id/authorization/policy/new/:policyType",
  element: <PolicyDetails />,
  breadcrumb: (t) => t("createPolicy"),
  handle: {
    access: "view-clients",
  },
};

export const toCreatePolicy = (params: NewPolicyParams): Partial<Path> => ({
  pathname: generateUnencodedPath(NewPolicyRoute.path, params),
});
