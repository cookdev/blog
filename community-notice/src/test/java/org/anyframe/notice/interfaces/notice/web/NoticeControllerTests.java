package org.anyframe.notice.interfaces.notice.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.anyframe.PortalNoticeApplication;
import org.anyframe.notice.application.NoticeService;
import org.anyframe.notice.interfaces.notice.facade.NoticeServiceFacade;
import org.anyframe.notice.interfaces.notice.facade.dto.NoticeDto;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = PortalNoticeApplication.class)
@WebAppConfiguration
public class NoticeControllerTests {
	
	@Mock
	private NoticeService mockNoticeService;

	@Mock
	private NoticeServiceFacade mockNoticeServiceFacade;
	
	@InjectMocks
	@Autowired
	private NoticeController noticeController;
	
	@Autowired
	private WebApplicationContext context;
	
	private MockMvc mvc;
	
	@Before
	public void setUp() throws Exception {
		// Mock setting
		MockitoAnnotations.initMocks(this);
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context).build();
	}

//	@Test
//	public void 공지목록을요청하는요청이들어왔을때_공지목록을리턴한다() throws Exception {
//		// given
//		JSONParser par = new JSONParser();
//
//		NoticeDto mockNoticeDto = new NoticeDto(1, "Test", "TDD is difficult", "2015-11-11");
//
//		List<NoticeDto> mockListNoticeDtos = new ArrayList<>();
//		mockListNoticeDtos.add(mockNoticeDto);
//
//		// when
//		when(mockNoticeServiceFacade.getAllNotice(new PageRequest(0, 20, Sort.Direction.DESC, "noticeId")).thenReturn(mockListNoticeDtos);
//
//		// then
//		String resultListNoticesJson = this.mvc.perform(get("/portal-notice/notices"))
//				.andReturn().getResponse().getContentAsString();
//
//		List<?> listNotices = (List<?>)par.parse(resultListNoticesJson);
//
//		verify(mockNoticeServiceFacade).getAllNotice();
//		assertNotNull(listNotices);
//	}

	@Test
	public void ID로공지사항을조회하면_공지ID에해당하는공지사항을리턴한다() throws Exception{
		// given
		JSONParser par = new JSONParser();
		int mockNoticeId = 1;

		NoticeDto mockNoticeDto = new NoticeDto(mockNoticeId, "2015년 12월 31일 서버점검합니다", "서버점검알림", "2015-11-11");


		// when
		when(mockNoticeServiceFacade.getNotice(mockNoticeId)).thenReturn(mockNoticeDto);

		// then
		String resultNoticeJson = this.mvc.perform(get("/portal-notice/notice/"+ mockNoticeId))
				.andReturn().getResponse().getContentAsString();

		JSONObject resultNotice = (JSONObject)par.parse(resultNoticeJson);
		verify(mockNoticeServiceFacade).getNotice(mockNoticeId);
		assertNotNull(resultNotice);
	}

	@Test
	public void POST요청이들어오면_공지사항을추가한다() throws Exception {
		// given
		int mockNoticeId = 1;
		Map<String, String> mockNoticeMap = new HashMap<>();
		mockNoticeMap.put("title", "Test");
		mockNoticeMap.put("content", "Test");
		mockNoticeMap.put("writer", "Test");
		mockNoticeMap.put("Date", null);

		//when
		when(mockNoticeService.createNotice(mockNoticeMap)).thenReturn(mockNoticeId);

		// then
		String resultId = this.mvc.perform(post("/portal-notice/notice/")
			.content(asJsonString(mockNoticeMap))
			.contentType(MediaType.APPLICATION_JSON)
			.accept(MediaType.APPLICATION_JSON)).andReturn().getResponse().getContentAsString();

		verify(mockNoticeService).createNotice(mockNoticeMap);
		assertNotNull(resultId, "1");
	}

	@Test
	public void PUT요청이들어오면_공지사항을수정한다() throws Exception{
		// given
		int mockNoticeId = 1;

		Map<String, String> mockNoticeMap = new HashMap<>();
		mockNoticeMap.put("noticeId", "1");
		mockNoticeMap.put("title", "Test");
		mockNoticeMap.put("content", "Test");
		mockNoticeMap.put("Date", null);

		// when
		when(mockNoticeService.updateNotice(mockNoticeMap)).thenReturn(mockNoticeId);

		// then
		String resultId = this.mvc.perform(put("/portal-notice/notice/" + mockNoticeId)
				.content(asJsonString(mockNoticeMap))
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)).andReturn().getResponse().getContentAsString();

		verify(mockNoticeService).updateNotice(mockNoticeMap);

		assertEquals(resultId,"1");
	}

	@Test
	public void DELETE요청이들어오면_공지사항을삭제한다() throws Exception {
		// given
		int mockNoticeId = 1;

		// when

		// then
		this.mvc.perform(delete("/portal-notice/notice/" + mockNoticeId));
		verify(mockNoticeService).deleteNotice(mockNoticeId);
	}

	public static String asJsonString(final Object obj) {
		try {
			final ObjectMapper mapper = new ObjectMapper();
			return mapper.writeValueAsString(obj);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
