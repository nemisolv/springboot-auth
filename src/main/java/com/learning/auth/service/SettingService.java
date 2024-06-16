package com.learning.auth.service;

import com.learning.auth.entity.Setting;
import com.learning.auth.helper.EmailSettingBag;

import java.util.List;

public interface SettingService {
    EmailSettingBag getEmailSettings();

}
