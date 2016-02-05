package org.anyframe.notice.application;

import org.anyframe.PortalNoticeApplication;
import org.anyframe.notice.domain.model.notice.Notice;
import org.anyframe.notice.domain.model.notice.NoticeRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.transaction.Transactional;
import java.text.SimpleDateFormat;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = PortalNoticeApplication.class)
@WebAppConfiguration
@Transactional
public class NoticeServiceTests {

	@Mock
	private NoticeRepository mockNoticeRepository;

	@InjectMocks
	@Autowired
	private NoticeService noticeService;

	@Autowired
	private WebApplicationContext context;

	private MockMvc mvc;

	@Value("TEST_TITLE")
	String mockTitle;

	@Value("TEST_CONTENT")
	String mockContent;

	int mockNoticeId;

	@Value("2015-01-01")
	String mockStringDate;

	Date mockDate = null;

	@Before
	public void setUp() throws Exception {
		// Mock setting
		MockitoAnnotations.initMocks(this);
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context).build();


		this.mockNoticeId = 1;
		this.mockDate = new SimpleDateFormat("yyyy-MM-dd").parse(this.mockStringDate);
	}

	@Test
	public void createNotice메서드가호출되면_noticeRepository의save메서드를호출한다(){
		// given
		Map<String, String> noticeMap = new HashMap<>();
		noticeMap.put("title", this.mockTitle);
		noticeMap.put("this.mockContent", this.mockContent);
		noticeMap.put("date", this.mockStringDate);

		Notice mockNotice = new Notice(this.mockNoticeId, this.mockTitle, this.mockContent, this.mockDate);
		int resultNoticeId = 0;

		// when
		when(mockNoticeRepository.save((Notice) any())).thenReturn(mockNotice);

		// then
		resultNoticeId = noticeService.createNotice(noticeMap);

		verify(mockNoticeRepository).save((Notice) any());
		assertEquals(mockNotice.getNoticeId(), resultNoticeId);
	}

	@Test
	public void updateNotice메서드가호출되면_noticeRepository의save메서드를호출한다(){
		// given
		Map<String, String> mockNoticeMap = new HashMap<>();
		mockNoticeMap.put("noticeId", Integer.toString(this.mockNoticeId));
		mockNoticeMap.put("title", this.mockTitle);
		mockNoticeMap.put("content", this.mockContent);
		mockNoticeMap.put("date", this.mockStringDate);

		Notice mockNotice = new Notice(this.mockNoticeId, this.mockTitle, this.mockContent, this.mockDate);

		// when
		when(mockNoticeRepository.save((Notice) any())).thenReturn(mockNotice);

		int resultId = noticeService.updateNotice(mockNoticeMap);

		// then
		verify(mockNoticeRepository).save((Notice) any());
		assertEquals(resultId, mockNotice.getNoticeId());
	}

	@Test
	public void deleteNotice메서드가호출되면_noticeRepostory의delete메서드를호출한다() {
		// given

		// when

		// then
		noticeService.deleteNotice(this.mockNoticeId);

		verify(mockNoticeRepository).delete(this.mockNoticeId);
	}

}