package org.anyframe.notice.interfaces.notice.facade.internal;

import org.anyframe.notice.domain.model.notice.Notice;
import org.anyframe.notice.domain.model.notice.NoticeRepository;
import org.anyframe.notice.interfaces.notice.facade.NoticeServiceFacade;
import org.anyframe.notice.interfaces.notice.facade.dto.NoticeDto;
import org.anyframe.notice.interfaces.notice.facade.internal.assembler.NoticeDtoAssembler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DefaultNoticeServiceFacade implements NoticeServiceFacade{

    @Autowired
    private NoticeRepository noticeRepository;

    @Override
    public List<NoticeDto> getAllNotice(PageRequest pageRequest) {
        NoticeDtoAssembler noticeDtoAssembler = new NoticeDtoAssembler();
        Page<Notice> currentPage = noticeRepository.findAll(pageRequest);
        List<Notice> listNotice = currentPage.getContent();
        List<NoticeDto> listNotices = new ArrayList<>();
        for (Notice notice : listNotice) {
            listNotices.add(noticeDtoAssembler.toNoticeDto(notice));
        }
        return listNotices;
    }

    @Override
    public NoticeDto getNotice(int noticeId) {
        NoticeDtoAssembler noticeDtoAssembler = new NoticeDtoAssembler();
        Notice notice = noticeRepository.findOne(noticeId);
        NoticeDto noticeDto = noticeDtoAssembler.toNoticeDto(notice);

        return noticeDto;
    }
}
