package org.anyframe.notice.interfaces.notice.facade;

import org.anyframe.PortalNoticeApplication;
import org.anyframe.notice.domain.model.notice.Notice;
import org.anyframe.notice.domain.model.notice.NoticeRepository;
import org.anyframe.notice.interfaces.notice.facade.dto.NoticeDto;
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

import java.text.SimpleDateFormat;
import java.util.*;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = PortalNoticeApplication.class)
@WebAppConfiguration
public class NoticeServiceFacadeTests {
    @Mock
    private NoticeRepository mockNoticeRepository;

    @InjectMocks
    @Autowired
    private NoticeServiceFacade noticeServiceFacade;

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

//    @Test
//    public void getAllNotice메서드가호출되면_공지목록을리턴한다() {
//        // given
//        Notice mockNotice = new Notice(this.mockNoticeId, this.mockTitle, this.mockContent, this.mockDate);
//
//        List<Notice> mockListNotices = new ArrayList<>();
//        mockListNotices.add(mockNotice);
//
//        // when
//        when(mockNoticeRepository.findAll()).thenReturn(mockListNotices);
//
//        // then
//        List<NoticeDto> resultNoticeList = noticeServiceFacade.getAllNotice();
//
//        verify(mockNoticeRepository).findAllByOrderByNoticeIdDesc();
//        assertNotNull(resultNoticeList);
//
//    }

    @Test
    public void getNoticeById메서드가호출되면_ID에해당하는공지사항상세를보여준다(){
        // given
        Notice mockNotice = new Notice(this.mockNoticeId, this.mockTitle, this.mockContent, new Date());

        // when
        when(mockNoticeRepository.findOne(this.mockNoticeId)).thenReturn(mockNotice);

        // then
        NoticeDto resultNoticeById = noticeServiceFacade.getNotice(this.mockNoticeId);

        verify(mockNoticeRepository).findOne(this.mockNoticeId);
        assertNotNull(resultNoticeById);
    }

}
