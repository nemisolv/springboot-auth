package com.learning.auth.repository;

import com.learning.auth.entity.Setting;
import com.learning.auth.entity.SettingCategory;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface SettingRepository extends CrudRepository<Setting,Long> {
    List<Setting> findByCategory(SettingCategory category);
}