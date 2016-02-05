package org.anyframe.notice.domain.model.notice;


import javax.persistence.*;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;

@Entity
public class Notice implements Serializable {

	private static final long serialVersionUID = 1L;

	private static final SimpleDateFormat DATE_FORMAT
			= new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");

	@Id
	@Column(name="notice_id")
	@GeneratedValue
	private int noticeId;
	
	private String title;
	
	private String content;
	
//	@Temporal(TemporalType.DATE)
	private Date date;

	public Notice(){}

	public Notice(String title, String content, Date date) {
		this.title = title;
		this.content = content;
		this.date = date;
	}
	public Notice(int noticeId, String title, String content,Date date) {
		this.noticeId = noticeId;
		this.title = title;
		this.content = content;
		this.date = date;
	}

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

	public Date getDate() {
		return date;
	}

	public void setDate(Date date) {
		this.date = date;
	}

	@Override
	public String toString() {
		return "Notice{" +
				"noticeId=" + noticeId +
				", title='" + title + '\'' +
				", content='" + content + '\'' +
				", date=" + date +
				'}';
	}

	// Date 타입을 제외한 필드 값이 동일한 경우 동일한 객체로 인식한다.
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		Notice notice = (Notice) o;

		if (noticeId != notice.noticeId) return false;
		if (title != null ? !title.equals(notice.title) : notice.title != null) return false;
		return (content != null ? !content.equals(notice.content) : notice.content != null);
	}

	@Override
	public int hashCode() {
		int result = noticeId;
		result = 31 * result + (title != null ? title.hashCode() : 0);
		result = 31 * result + (content != null ? content.hashCode() : 0);
		return result;
	}
}
