package org.anyframe.notice.interfaces.notice.web;

import org.anyframe.notice.application.NoticeService;
import org.anyframe.notice.interfaces.notice.facade.NoticeServiceFacade;
import org.anyframe.notice.interfaces.notice.facade.dto.NoticeDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
public class NoticeController {
	
	@Autowired
	private NoticeService noticeService;

	@Autowired
	private NoticeServiceFacade noticeServiceFacade;

	@RequestMapping(value="/portal-notice/notices", method= RequestMethod.GET, params = {"pageSize", "currentPage"})
	public List<NoticeDto> listNotices(@RequestParam("pageSize") int pageSize, @RequestParam("currentPage") int currentPage) {
		PageRequest pageRequest = new PageRequest(currentPage, pageSize, Sort.Direction.DESC, "noticeId");
		return noticeServiceFacade.getAllNotice(pageRequest);
	}

	@RequestMapping(value="/portal-notice/notice/{noticeId}",method=RequestMethod.GET)
	public NoticeDto getNotice(@PathVariable("noticeId") int noticeId) {
		return noticeServiceFacade.getNotice(noticeId);
	}

	@RequestMapping(value="/portal-notice/notice/{noticeId}", method=RequestMethod.PUT)
	public int updateNotice(@RequestBody Map<String,String> notice) {
		return noticeService.updateNotice(notice);
	}

	@RequestMapping(value="/portal-notice/notice",method=RequestMethod.POST)
	public int createNotice(@RequestBody Map<String,String> notice) {
		return noticeService.createNotice(notice);
	}

	@RequestMapping(value="/portal-notice/notice/{noticeId}",method=RequestMethod.DELETE)
	public ResponseEntity deleteNotice(@PathVariable("noticeId") int noticeId) {
		noticeService.deleteNotice(noticeId);

		return new ResponseEntity<>(noticeId, HttpStatus.OK);
	}

}
