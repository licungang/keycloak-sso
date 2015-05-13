package org.keycloak.services.resources.admin;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import javax.ws.rs.NotFoundException;
import org.keycloak.events.AdminEventBuilder;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.RoleRepresentation;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriInfo;

import java.util.List;
import java.util.Set;

/**
 * Sometimes its easier to just interact with roles by their ID instead of container/role-name
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RoleByIdResource extends RoleResource {
    protected static final Logger logger = Logger.getLogger(RoleByIdResource.class);
    private final RealmModel realm;
    private final RealmAuth auth;
    private AdminEventBuilder adminEvent;

    @Context
    protected KeycloakSession session;

    public RoleByIdResource(RealmModel realm, RealmAuth auth, AdminEventBuilder adminEvent) {
        super(realm);

        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent;
    }

    /**
     * Get a specific role's representation
     *
     * @param id id of role
     * @return
     */
    @Path("{role-id}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public RoleRepresentation getRole(final @PathParam("role-id") String id) {
        RoleModel roleModel = getRoleModel(id);
        auth.requireView();
        
        adminEvent.operation(OperationType.VIEW).resourcePath(session.getContext().getUri().getPath()).success();

        return getRole(roleModel);
    }

    protected RoleModel getRoleModel(String id) {
        RoleModel roleModel = realm.getRoleById(id);
        if (roleModel == null) {
            throw new NotFoundException("Could not find role with id: " + id);
        }

        RealmAuth.Resource r = null;
        if (roleModel.getContainer() instanceof RealmModel) {
            r = RealmAuth.Resource.REALM;
        } else if (roleModel.getContainer() instanceof ClientModel) {
            r = RealmAuth.Resource.CLIENT;
        } else if (roleModel.getContainer() instanceof UserModel) {
            r = RealmAuth.Resource.USER;
        }
        auth.init(r);
        
        adminEvent.operation(OperationType.VIEW).resourcePath(session.getContext().getUri().getPath()).success();

        return roleModel;
    }

    /**
     * Delete this role
     *
     * @param id id of role
     */
    @Path("{role-id}")
    @DELETE
    @NoCache
    public void deleteRole(final @PathParam("role-id") String id) {
        RoleModel role = getRoleModel(id);
        auth.requireManage();
        deleteRole(role);
        adminEvent.operation(OperationType.DELETE).resourcePath(session.getContext().getUri().getPath()).success();
    }

    /**
     * Update this role
     *
     * @param id id of role
     * @param rep
     */
    @Path("{role-id}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public void updateRole(final @PathParam("role-id") String id, final RoleRepresentation rep) {
        RoleModel role = getRoleModel(id);
        auth.requireManage();
        updateRole(rep, role);
        adminEvent.operation(OperationType.UPDATE).resourcePath(session.getContext().getUri().getPath()).representation(rep).success();
    }

    /**
     * Make this role a composite role by associating some child roles to it.
     *
     * @param id
     * @param roles
     */
    @Path("{role-id}/composites")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addComposites(final @PathParam("role-id") String id, List<RoleRepresentation> roles) {
        RoleModel role = getRoleModel(id);
        auth.requireManage();
        addComposites(roles, role);
        adminEvent.operation(OperationType.ACTION).resourcePath(session.getContext().getUri().getPath()).representation(roles).success();
        
    }

    /**
     * If this role is a composite, return a set of its children
     *
     * @param id
     * @return
     */
    @Path("{role-id}/composites")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getRoleComposites(final @PathParam("role-id") String id) {

        if (logger.isDebugEnabled()) logger.debug("*** getRoleComposites: '" + id + "'");
        RoleModel role = getRoleModel(id);
        auth.requireView();
        adminEvent.operation(OperationType.VIEW).resourcePath(session.getContext().getUri().getPath()).success();
        return getRoleComposites(role);
    }

    /**
     * Return a set of realm-level roles that are in the role's composite
     *
     * @param id
     * @return
     */
    @Path("{role-id}/composites/realm")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getRealmRoleComposites(final @PathParam("role-id") String id) {
        RoleModel role = getRoleModel(id);
        auth.requireView();
        adminEvent.operation(OperationType.VIEW).resourcePath(session.getContext().getUri().getPath()).success();
        return getRealmRoleComposites(role);
    }

    /**
     * Return a set of client-level roles for a specific client that are in the role's composite
     *
     * @param id
     * @param appName
     * @return
     */
    @Path("{role-id}/composites/clients/{app}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getClientRoleComposites(final @PathParam("role-id") String id,
                                                                final @PathParam("app") String appName) {
        RoleModel role = getRoleModel(id);
        auth.requireView();
        ClientModel app = realm.getClientByClientId(appName);
        if (app == null) {
            throw new NotFoundException("Could not find client: " + appName);

        }
        adminEvent.operation(OperationType.VIEW).resourcePath(session.getContext().getUri().getPath()).success();
        return getClientRoleComposites(app, role);
    }

    /**
     * Return a set of client-level roles for a specific client that are in the role's composite
     *
     * @param id
     * @param appId
     * @return
     */
    @Path("{role-id}/composites/clients-by-id/{appId}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getClientByIdRoleComposites(final @PathParam("role-id") String id,
                                                                final @PathParam("appId") String appId) {
        RoleModel role = getRoleModel(id);
        auth.requireView();
        ClientModel app = realm.getClientById(appId);
        if (app == null) {
            throw new NotFoundException("Could not find client: " + appId);

        }
        adminEvent.operation(OperationType.VIEW).resourcePath(session.getContext().getUri().getPath()).success();
        return getClientRoleComposites(app, role);
    }

    /**
     * Remove the listed set of roles from this role's composite
     *
     * @param id
     * @param roles
     */
    @Path("{role-id}/composites")
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteComposites(final @PathParam("role-id") String id, List<RoleRepresentation> roles) {
        RoleModel role = getRoleModel(id);
        auth.requireManage();
        deleteComposites(roles, role);
        adminEvent.operation(OperationType.DELETE).resourcePath(session.getContext().getUri().getPath()).success();
    }

}
