package com.app.ms_security.dto;

import lombok.Data;

@Data
public class PermissionFlagDto {
    private boolean view;
    private boolean list;
    private boolean create;
    private boolean update;
    private boolean delete;
}