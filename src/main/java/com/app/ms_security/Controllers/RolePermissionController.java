package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Role;
import com.app.ms_security.Models.Permission;
import com.app.ms_security.Models.RolePermission;
import com.app.ms_security.Models.UserRole;
import com.app.ms_security.Repositories.RoleRepository;
import com.app.ms_security.Repositories.PermissionRepository;
import com.app.ms_security.Repositories.RolePermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("api/role-permission")
public class RolePermissionController {
    @Autowired
    private RolePermissionRepository theRolePermissionRepository;
    @Autowired
    private PermissionRepository thePermissionRepository;
    @Autowired
    private RoleRepository theRoleRepository;

    @GetMapping("")
    public List<RolePermission> find() {
        return this.theRolePermissionRepository.findAll();

    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("role/{roleId}/permission/{permissionId}")
    public RolePermission create(@PathVariable String roleId,
                                 @PathVariable String permissionId){
        Role theRole=this.theRoleRepository.findById(roleId)
                .orElse(null);
        Permission thePermission=this.thePermissionRepository.findById((permissionId))
                .orElse(null);
        if(theRole!=null && thePermission!=null){
            RolePermission newRolePermission=new RolePermission();
            newRolePermission.setRole(theRole);
            newRolePermission.setPermission(thePermission);
            return this.theRolePermissionRepository.save(newRolePermission);
        }else{
            return null;
        }
    }
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        RolePermission theRolePermission = this.theRolePermissionRepository
                .findById(id)
                .orElse(null);
        if (theRolePermission != null) {
            this.theRolePermissionRepository.delete(theRolePermission);
        }
    }
    @GetMapping("role/{roleId}")
    public List<Permission> findPermissionsByRole(@PathVariable String roleId){
        return this.theRolePermissionRepository.getPermissionsByRole(roleId).stream().map(RolePermission::getPermission).toList();
    }

    @DeleteMapping("role/{roleId}/permission/{permissionId}")
    public void getRolePermissionByRoleAndPermission(@PathVariable String roleId, @PathVariable String permissionId){
        RolePermission theRolePermission = this.theRolePermissionRepository.getRolePermissionByRoleAndPermission(roleId, permissionId);
        if (theRolePermission != null) {
            this.theRolePermissionRepository.delete(theRolePermission);
        } else {
            throw new RuntimeException("No se encontró relación UserRole con ese userId y roleId");
        }
    }

    @GetMapping("permissionsToAdd/{roleId}")
    public List<Permission> getRolesToAddUser(@PathVariable String roleId) {
        List<RolePermission> rolePermissions = theRolePermissionRepository.getPermissionsByRole(roleId);
        List<String> assignedPermissionIds = rolePermissions.stream()
                .map(ur -> ur.getPermission().get_id())
                .toList();
        return thePermissionRepository.findByIdNotIn(assignedPermissionIds);
    }
}
