package org.anyframe.notice.domain.model.notice;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface NoticeRepository extends JpaRepository<Notice, Integer> {

    List<Notice> findAllByOrderByNoticeIdDesc();
}
