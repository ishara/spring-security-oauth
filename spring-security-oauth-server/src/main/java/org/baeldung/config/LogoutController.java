package org.baeldung.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.ExpiringSession;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collection;
import java.util.Set;

/**
 * Created by ishara on 4/24/2017.
 */
@RestController
public class LogoutController {

    @Autowired
    FindByIndexNameSessionRepository<? extends ExpiringSession> sessions;

    @RequestMapping("/logout_sso")
    public void logout(Principal principal)
    {
        Collection<? extends ExpiringSession> usersSessions = this.sessions
                .findByIndexNameAndIndexValue(
                        FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
                        principal.getName())
                .values();
        for (ExpiringSession expiringSession : usersSessions) {
            sessions.delete(expiringSession.getId());
        }

    }
    @RequestMapping("/")
    public String index(Principal principal, Model model) {
        Collection<? extends ExpiringSession> usersSessions = this.sessions
                .findByIndexNameAndIndexValue(
                        FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
                        principal.getName())
                .values();
        model.addAttribute("sessions", usersSessions);
        return "index";
    }
    // end::findbyusername[]

    @RequestMapping(value = "/sessions/{sessionIdToDelete}", method = RequestMethod.DELETE)
    public String removeSession(Principal principal,
                                @PathVariable String sessionIdToDelete) {
        Set<String> usersSessionIds = this.sessions.findByIndexNameAndIndexValue(
                FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
                principal.getName()).keySet();
        if (usersSessionIds.contains(sessionIdToDelete)) {
            this.sessions.delete(sessionIdToDelete);
        }

        return "redirect:/";
    }
}
