package org.anyframe.notice.application;

import java.util.Map;

public interface NoticeService {

	int createNotice(Map<String, String> notice);

	int updateNotice(Map<String, String> notice);

	void deleteNotice(int noticeId);

}
