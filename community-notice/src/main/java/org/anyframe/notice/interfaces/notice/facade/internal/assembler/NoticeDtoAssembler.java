package org.anyframe.notice.interfaces.notice.facade.internal.assembler;

import org.anyframe.notice.domain.model.notice.Notice;
import org.anyframe.notice.interfaces.notice.facade.dto.NoticeDto;

import java.text.SimpleDateFormat;

/**
 * Created by SDS on 2015-11-26.
 */
public class NoticeDtoAssembler {

    private static final SimpleDateFormat DATE_FORMAT
            = new SimpleDateFormat("yyyy/MM/dd hh:mm:ss");

    public NoticeDto toNoticeDto(Notice notice) {
        NoticeDto noticeDto = new NoticeDto(
                notice.getNoticeId(),
                notice.getTitle(),
                notice.getContent(),
                DATE_FORMAT.format(notice.getDate())
        );

        return noticeDto;
    }
}
