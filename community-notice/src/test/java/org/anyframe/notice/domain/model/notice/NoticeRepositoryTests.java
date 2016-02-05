package org.anyframe.notice.domain.model.notice;

import org.anyframe.PortalNoticeApplication;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import javax.transaction.Transactional;
import java.util.Date;

import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = PortalNoticeApplication.class)
@WebAppConfiguration
@Transactional
public class NoticeRepositoryTests {

	@Autowired
	private NoticeRepository noticeRepository;

	// Mock Data
	Notice mockNotice;
	int mockNoticeId;

	@Test
	public void findAll를호출하면_DB에서공지목록을조회한다() {
		// given
		mockNoticeCreate();

		// when

		// then
		assertTrue(noticeRepository.findAll().size() > 0);
	}

	@Test
	public void noticeId로findOne을호출하면_DB에서공지사항을조회한다() {
		// given
		mockNoticeCreate();

		// when

		// then
		Notice resultNotice = noticeRepository.findOne(this.mockNoticeId);
		assertNotNull(resultNotice);
		assertEquals(resultNotice.getNoticeId(), this.mockNoticeId);
	}

	@Test
	public void id없이save를호출하면_DB에공지사항을추가한다() {
		// given
		Notice newNotice = new Notice("TEST_TITLE", "TEST_CONTENT", new Date());

		// when

		// then
		Notice resultNotice = noticeRepository.save(newNotice);
		assertEquals(newNotice.getTitle(), resultNotice.getTitle());
	}

	@Test
	public void id를가지고save를호출하면_DB에공지사항을수정한다(){
		// given
		mockNoticeCreate();
		this.mockNotice.setTitle("테스트 데이터 수정");

		// when

		// then
		Notice resultNotice = noticeRepository.save(this.mockNotice);

		assertEquals(resultNotice.getTitle(), this.mockNotice.getTitle());
	}

	@Test
	public void  deleteNotice를호출하면_DB에공지사항을삭제한다(){
		// given
		mockNoticeCreate();

		// when

		// then
		noticeRepository.delete(this.mockNoticeId);
		assertNull(noticeRepository.findOne(this.mockNoticeId));
	}

	public void mockNoticeCreate() {
		// mock notice setting
		Notice notice = new Notice("TEST_TITLE", "TEST_CONTENT", new Date());
		this.mockNotice = noticeRepository.save(notice);

		// mock id setting
		this.mockNoticeId = this.mockNotice.getNoticeId();
	}
}
