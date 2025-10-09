package com.app.ms_security.Controllers;

import com.app.ms_security.Models.*;
import com.app.ms_security.Repositories.RoleRepository;
import com.app.ms_security.Repositories.PermissionRepository;
import com.app.ms_security.Repositories.RolePermissionRepository;
import com.app.ms_security.dto.PermissionFlagDto;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.*;
import java.util.stream.*;

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
    @PostMapping("sustentacion")
    public List<Permission> findByLista(@RequestBody List<Integer> numbers) {
        numbers.sort(Comparator.reverseOrder());
        List<RolePermission> rolePermissions =this.theRolePermissionRepository.findAll() ;
        HashMap<String,Integer> map = new HashMap<>();
        for (RolePermission rolePermission : rolePermissions) {
            Permission permission=rolePermission.getPermission();
            int value =map.getOrDefault(permission.get_id(),0);
            map.put(permission.get_id(), value + 1);
        }
        List<String> permisosID=new ArrayList<>();
        for(Integer number : numbers){
             permisosID.addAll(map.entrySet().stream()
                    .filter(entry -> entry.getValue() == number)
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toList()));

        }
        List<Permission>permissions=new ArrayList<>();
        for(String key : permisosID){
            Permission permission=thePermissionRepository.findById(key).orElse(null);
            permissions.add(permission);
        }
        return permissions;






    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("role/{roleId}/permission/{permissionId}")
    public RolePermission create(@PathVariable String roleId,
                                 @PathVariable String permissionId) {
        Role theRole = this.theRoleRepository.findById(roleId)
                .orElse(null);
        Permission thePermission = this.thePermissionRepository.findById((permissionId))
                .orElse(null);
        if (theRole != null && thePermission != null) {
            RolePermission newRolePermission = new RolePermission();
            newRolePermission.setRole(theRole);
            newRolePermission.setPermission(thePermission);
            return this.theRolePermissionRepository.save(newRolePermission);
        } else {
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
    public List<Permission> findPermissionsByRole(@PathVariable String roleId) {
        return this.theRolePermissionRepository.getPermissionsByRole(roleId).stream().map(RolePermission::getPermission).toList();
    }

    @DeleteMapping("role/{roleId}/permission/{permissionId}")
    public void getRolePermissionByRoleAndPermission(@PathVariable String roleId, @PathVariable String permissionId) {
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
    @PatchMapping("check")
    public  void  saveCheckValidate(@RequestBody Map <String, Object>theResponse,  final HttpServletResponse response) {
        String method=theResponse.get("method").toString();
        String model=theResponse.get("model").toString();
        String roleId=theResponse.get("roleId").toString();
        Boolean cheked=theResponse.get("checked").toString().equals("true");
        Role role =theRoleRepository.findById(roleId).orElse(null);
        if (role == null) {response.setStatus(HttpServletResponse.SC_BAD_REQUEST);return ;}

        String url="/api/"+model+"s";
        if(method.equals("view") || method.equals("update")||method.equals("delete")) url=url+"/?";
        switch (method) {
            case "view","list"->method="GET";
            case "update"->method="PATCH";
            case "delete"->method="DELETE";
            case "add"->method="POST";
            default -> method="";
        }
        Permission permission =thePermissionRepository.getPermission(url,method);
        if (permission == null) {response.setStatus(HttpServletResponse.SC_BAD_REQUEST);return ;}
        RolePermission theRolePermission =theRolePermissionRepository.getRolePermission(roleId, permission.get_id());
        if (cheked) {
            if (theRolePermission!=null) {response.setStatus(HttpServletResponse.SC_BAD_REQUEST);}
            else {
                RolePermission newRolePermission = new RolePermission();
                newRolePermission.setPermission(permission);
                newRolePermission.setRole(role);
                this.theRolePermissionRepository.save(newRolePermission);

            }

        }else {
            if (theRolePermission==null) {response.setStatus(HttpServletResponse.SC_BAD_REQUEST);return ;}
            else {
                theRolePermissionRepository.delete(theRolePermission);
            }
        }


    }
    @GetMapping("role/{roleId}/permissions")
    public Map <String, PermissionFlagDto> getPermissionsForCheck(@PathVariable String roleId) {
        List<Permission> permissions = findPermissionsByRole(roleId);
        List<Permission> totalPermission=thePermissionRepository.findAll();
        Map<String, PermissionFlagDto> result = new LinkedHashMap<>();
        for(Permission permission:totalPermission) {
            final String model  = permission.getModel().trim();
            result.computeIfAbsent(model, k -> new PermissionFlagDto());
        }

        for (Permission p : permissions){
            if (p == null || p.getModel() == null || p.getMethod() == null || p.getUrl() == null) continue;

            final String model  = p.getModel().trim();
            final String method = p.getMethod().trim().toUpperCase();
            final String url    = p.getUrl().trim();

            PermissionFlagDto flags = result.computeIfAbsent(model, k -> new PermissionFlagDto());
            switch (method) {
                case "GET" -> {
                    if (url.endsWith("?")) flags.setView(true);
                    else flags.setList(true);
                }
                case "POST" -> flags.setCreate(true);
                case "PUT", "PATCH" -> flags.setUpdate(true);
                case "DELETE" -> flags.setDelete(true);
                default -> {}
            }

        }
        return result;
    }
}
