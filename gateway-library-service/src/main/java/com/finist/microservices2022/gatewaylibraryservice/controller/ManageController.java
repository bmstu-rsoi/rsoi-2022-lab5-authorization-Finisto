package com.finist.microservices2022.gatewaylibraryservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/manage")
public class ManageController {

    public ManageController() {
    }

    @GetMapping("/health")
    public ResponseEntity<?> healthCheck(){
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
