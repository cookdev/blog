package org.anyframe.notice.application.internal;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

import org.anyframe.notice.application.NoticeService;
import org.anyframe.notice.domain.model.notice.Notice;
import org.anyframe.notice.domain.model.notice.NoticeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class DefaultNoticeService implements NoticeService {

	@Autowired
	private NoticeRepository noticeRepository;
	
	@Override
	public int createNotice(Map<String, String> noticeMap) {
		Date writeDate = new Date(System.currentTimeMillis());

		Notice notice = new Notice(
				noticeMap.get("title"),
				noticeMap.get("content"),
				writeDate);

		Notice resultNotice = noticeRepository.save(notice);

		return resultNotice.getNoticeId();
	}

	@Override
	public int updateNotice(Map<String, String> noticeMap) {
		Date writeDate = new Date(System.currentTimeMillis());

		Notice notice = new Notice(Integer.parseInt(noticeMap.get("noticeId")),
				noticeMap.get("title"),
				noticeMap.get("content"),
				writeDate);

		Notice resultNotice = noticeRepository.save(notice);

		return resultNotice.getNoticeId();
	}

	@Override
	public void deleteNotice(int noticeId) {
		noticeRepository.delete(noticeId);
	}

}
