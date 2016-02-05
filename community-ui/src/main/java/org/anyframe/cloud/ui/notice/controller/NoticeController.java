package org.anyframe.cloud.ui.notice.controller;

import org.anyframe.cloud.ui.notice.model.Notice;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by y.gwak on 2015-11-23.
 */
@RestController("NoticeController")
public class NoticeController {


    @RequestMapping(value="/portal-notice/notices", method = RequestMethod.GET)
    public List<Notice> listNotice() {
        List<Notice> noticeList = new ArrayList<>();

        noticeList.add(new Notice(1, "[알림] 서버 정기 작업 일정 알려드립니다. ( 10/1(수) 15:00 ~ 10/1(수) 18:00 )", "10/1(수) 15:00 ~ 10/1(수) 18:00 로 예정된 서버 정기 작업 일정을 알려드립니다.\n" +
                "이 시간 동안 Anyframe Java 오픈소스 커뮤니티 사용을 포함하여 Anyframe Java 개발 서버를 통해 제공하는 개발 환경에 접근이 제한되므로 사용에 참고하시기 바랍니다.\n" +
                "\n" +
                "[작업 일시]\n" +
                "10/1(수) 15:00 ~ 10/1(수) 18:00\n" +
                "\n" +
                "[사용 제한 대상]\n" +
                "1) Anyframe Java 오픈소스 커뮤니티 사이트(다운로드 페이지, 매뉴얼 사이트, Forum 등 모두 제한됨)\n" +
                "2) Subversion(형상관리 서버)\n" +
                "3) CTIP(빌드 서버)\n" +
                "4) JIRA(이슈 관리 시스템)\n" +
                "5) Anyframe Maven Repository(라이브러리 저장소)\n" +
                "\n" +
                "문의사항이 있으신 경우 관리자 이메일(anyframe@samsung.com)로 연락주시기 바랍니다.\n" +
                "\n" +
                "감사합니다.", "수, 10/01/2014 - 10:00"));

        noticeList.add(new Notice(2, "Anyframe Java Core 5.6.0이 릴리즈되었습니다.", "Spring 버전이 3.2.2.RELEASE에서 4.0.0.RELEASE로 업그레이드 되었습니다.\n" +
                "Spring 4.0의 주요 특징은 다음과 같습니다.\n" +
                "Java Baseline 변경\n" +
                "Java SE 6 (JDK 6) 이상\n" +
                "Java EE 6 / Servlet 2.5 이상\n" +
                "추가된 주요 기능\n" +
                "Java SE 8의 주요 기능 제공 (Baseline은 6이지만, 8의 주요 기능을 사용할 수 있게 합니다.)\n" +
                "Java EE 6/7의 주요 기능 제공 (사용할 기능에 따라서, WAS의 버전을 선택해야 합니다.)\n" +
                "Groovy DSL 지원\n" +
                "쉽고 간결한 문법을 사용하므로 코드의 가독성과 유지보수성이 좋습니다.\n" +
                "기존 자바소스코드 및 라이브러리와의 통합이 가능합니다.\n" +
                "Core Container의 사용성 향상\n" +
                "Qualifier를 Generic type으로 사용할 수 있고 @Orderd, @Description, @PropertySources 등의 annotation 지원으로 사용 편의성이 향상되었습니다.\n" +
                "Web MVC 사용성 향상\n" +
                "Servlet 3.0+, WebSocket 및 Timezone 정보를 지원합니다.\n" +
                "테스트 지원 패키지 보강\n" +
                "meta-annotations, SocketUtils 등을 지원하여 테스트 편의성이 향상되었습니다.", "금, 05/23/2014 - 20:19"));

        noticeList.add(new Notice(3, "[알림] 서버 정기 작업 일정 알려드립니다. (11/17(토) 18:00 ~ 11/18(일) 12:00)", "11/17(토) 18:00 ~ 11/18(일) 12:00 로 예정된 서버 정기 작업 일정을 알려드립니다.\n" +
                "이 시간 동안 Anyframe Java 오픈소스 커뮤니티 사용을 포함하여 Anyframe Java 개발 서버를 통해 제공하는 개발 환경에 접근이 제한되므로 사용에 참고하시기 바랍니다.\n" +
                "\n" +
                "[작업 일시]\n" +
                "11/17(토) 18:00 ~ 11/18(일) 12:00\n" +
                "\n" +
                "[사용 제한 대상]\n" +
                "1) Anyframe Java 오픈소스 커뮤니티 사이트(다운로드 페이지, 매뉴얼 사이트, Forum 등 모두 제한됨)\n" +
                "2) Subversion(형상관리 서버)\n" +
                "3) CTIP(빌드 서버)\n" +
                "4) JIRA(이슈 관리 시스템)\n" +
                "5) Anyframe Maven Repository(라이브러리 저장소)\n" +
                "\n" +
                "문의사항이 있으신 경우 관리자 이메일(anyframe@samsung.com)로 연락주시기 바랍니다.\n" +
                "\n" +
                "감사합니다.", "금, 11/09/2012 - 11:23"));

        return noticeList;
    }
}
