package com.example.controller;

import com.example.service.FpeEncryptorService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class FpeController {
    private final FpeEncryptorService fpeEncryptorService;

    @GetMapping("/fpe-encrypt")
    public ResponseEntity<String> fpeEncryption(@RequestParam String key) {
        return ResponseEntity.ok(fpeEncryptorService.FPEEncryption(key));
    }

    @GetMapping("/fpe-decrypt")
    public ResponseEntity<String> fpeDencryption(@RequestParam String key) {
        return ResponseEntity.ok(fpeEncryptorService.FPEDecryption(key));
    }
}
