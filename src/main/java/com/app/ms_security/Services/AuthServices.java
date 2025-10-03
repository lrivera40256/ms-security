package com.app.ms_security.Services;

import com.app.ms_security.Models.*;
import com.app.ms_security.Repositories.RolePermissionRepository;
import com.app.ms_security.Repositories.UserRepository;
import com.app.ms_security.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@Service
public class AuthServices {
    @Autowired
    private UserRoleRepository theUserRoleRepository;
    @Autowired
    private RolePermissionRepository theRolePermissionRepository;

    public List<Permission>  getRolesByUser(User user){
        ArrayList<Permission> permissions = new ArrayList<>();
        List<UserRole> userRoles = theUserRoleRepository.getRolesByUser(user.get_id());
        for(UserRole userRole : userRoles){
            List<RolePermission> rolePermissions =theRolePermissionRepository.getPermissionsByRole(userRole.getRole().get_id());
            for(RolePermission rolePermission : rolePermissions){
                permissions.add(rolePermission.getPermission());
            }
        }
        return permissions;

    }

}
