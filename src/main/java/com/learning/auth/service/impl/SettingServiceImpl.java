package com.learning.auth.service.impl;

import com.learning.auth.entity.Setting;
import com.learning.auth.entity.SettingCategory;
import com.learning.auth.helper.EmailSettingBag;
import com.learning.auth.repository.SettingRepository;
import com.learning.auth.service.SettingService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SettingServiceImpl implements SettingService {
    private final SettingRepository settingRepo;


    @Override
    public EmailSettingBag getEmailSettings() {
        List<Setting> settings = settingRepo.findByCategory(SettingCategory.MAIL_SERVER);
        return new EmailSettingBag(settings);
    }
}
