package org.anyframe.notice.interfaces.notice.facade.dto;

public class NoticeDto {

    public NoticeDto(int noticeId, String title, String content, String date) {
        this.noticeId = noticeId;
        this.title = title;
        this.content = content;
        this.date = date;
    }

    private int noticeId;

    private String title;

    private String content;

    private String date;

    public int getNoticeId() {
        return noticeId;
    }

    public void setNoticeId(int noticeId) {
        this.noticeId = noticeId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

}
