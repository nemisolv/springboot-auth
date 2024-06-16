package com.learning.auth.helper;

import com.learning.auth.entity.Setting;
import lombok.AllArgsConstructor;

import java.util.List;

@AllArgsConstructor
public class SettingBag {
    private List<Setting> settingList;


    public Setting get(String key) {
        int index = settingList.indexOf(new Setting(key));
        if (index >= 0) return settingList.get(index);
        return null;
    }

    public String getValue(String key) {
        Setting setting = get(key);
        if (setting != null) return setting.getValue().trim();
        return null;
    }

    public void updateValue(String key, String value) {
        Setting setting = get(key);
        if (setting != null) {
            setting.setValue(value);
        }
    }

    public List<Setting> list() {
        return settingList;
    }
}
