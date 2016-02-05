package org.anyframe.notice.interfaces.notice.facade;

import org.anyframe.notice.interfaces.notice.facade.dto.NoticeDto;
import org.springframework.data.domain.PageRequest;

import java.util.List;

public interface NoticeServiceFacade {

    List<NoticeDto> getAllNotice(PageRequest pageRequest);

    NoticeDto getNotice(int noticeId);
}
