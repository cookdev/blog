//package org.anyframe.cloud.user;
//
//import RegistrationService;
//import RegisteredUser;
//import UserRepository;
//import org.junit.Before;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.MockitoAnnotations;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.SpringApplicationConfiguration;
//import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
//import org.springframework.test.context.web.WebAppConfiguration;
//import org.springframework.test.web.servlet.MockMvc;
//import org.springframework.test.web.servlet.setup.MockMvcBuilders;
//import org.springframework.transaction.annotation.Transactional;
//import org.springframework.web.context.WebApplicationContext;
//
//import static junit.framework.Assert.assertEquals;
//import static junit.framework.Assert.assertTrue;
//import static junit.framework.TestCase.assertNotNull;
//import static org.mockito.Mockito.verify;
//import static org.mockito.Mockito.when;
//import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
//
///**
// * Created by Hahn on 2015-11-25.
// */
//
//@RunWith(SpringJUnit4ClassRunner.class)
//@SpringApplicationConfiguration(classes = CommunityUserApplication.class)
//@WebAppConfiguration
//public class UserRegistrationTest {
//
//    @Mock
//    private UserRepository mockUserRepository;
//
//    @InjectMocks
//    @Autowired
//    private RegistrationService mockUserRegisterService;
//
//    @Autowired
//    private WebApplicationContext context;
//
//    private MockMvc mvc;
//
//    RegisteredUser newUser;
//    @Before
//    public void setUp() throws Exception{
//        // Mock setting
//        MockitoAnnotations.initMocks(this);
//        this.mvc = MockMvcBuilders.webAppContextSetup(this.context).build();
//
//        newUser = new RegisteredUser("userId", "test", "test","email","picture");
//
//    }
//
//    @Test
//    @Transactional
//    public void 회원등록_서비스를_호출하면_회원이등록된다() throws Exception {
//        String userId = "testId";
//
//        when(mockUserRepository.save(newUser)).thenReturn(newUser);
//
//        RegisteredUser registeredUser = mockUserRegisterService.registerNewUser(newUser);
//
//        verify(mockUserRepository).save(newUser);
//        assertTrue(newUser.equals(newUser));
//    }
//
//    @Test
//    @Transactional
//    public void 회원정보_조회를_호출하면_해당_회원정보가_조회된다() {
//        String userId = "userId";
//        when(mockUserRepository.findOne(userId)).thenReturn(this.newUser);
//
//        RegisteredUser result = mockUserRegisterService.getUserById(userId);
//
//        verify(mockUserRepository).findOne(userId);
//        assertEquals(userId, result.getUserId());
//
//    }
//
//    @Test
//    @Transactional
//    public void 회원정보_수정을_호출하면_해당_회원정보가_수정된다() {
//        String modifyName = "modifyName";
//        newUser.setUserName(modifyName);
//        when(mockUserRepository.save(newUser)).thenReturn(newUser);
//
//        RegisteredUser result = mockUserRegisterService.modifyUser(newUser);
//
//        verify(mockUserRepository).save(newUser);
//        assertEquals(result.getUserName(), modifyName);
//    }
//
//    @Test
//    @Transactional
//    public void 회원정보_삭제를_호출하면_해당_회원정보가_삭제된다() {
//
//        String userIdForDelete = "userId";
//
//        mockUserRegisterService.deleteUser(userIdForDelete);
//
//        verify(mockUserRepository).delete(userIdForDelete);
//    }
//
//    @Test
//    @Transactional
//    public void 내정보를조회한다() throws Exception {
//
//        String userId = "userId";
//        when(mockUserRepository.findOne(userId)).thenReturn(this.newUser);
//
//        RegisteredUser result = mockUserRepository.findOne(userId);
//        assertTrue(this.newUser.equals(result));
//    }
//
//    @Test
//    @Transactional
//    public void 회원을생성한다() throws Exception {
//
//        when(mockUserRepository.save(newUser)).thenReturn(newUser);
//        when(mockUserRepository.findOne("userId")).thenReturn(newUser);
//        RegisteredUser resultUser = mockUserRepository.save(newUser);
//        RegisteredUser findUser = mockUserRepository.findOne("userId");
//        assertEquals(resultUser.getUserId(), findUser.getUserId());
//    }
//}
