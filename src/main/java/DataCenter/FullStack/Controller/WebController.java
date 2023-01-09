package DataCenter.FullStack.Controller;

import DataCenter.FullStack.Model.AppUser;
import DataCenter.FullStack.Respository.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(value = "*",maxAge = 3600)
@RequestMapping("/api/test")
public class WebController {

    @Autowired
    AppUserRepository appUserRepository;

    @PostMapping(path = "/user/post")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR')")
    AppUser postUser(@RequestBody AppUser user){
        return appUserRepository.save(user);
    }

    @GetMapping(path = "/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('MODERATOR')")
    List<AppUser> getUser(){
        List<AppUser> allUser = appUserRepository.findAll();
        return allUser;
    }

    @GetMapping(path = "/user/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('MODERATOR')")
    AppUser getUseById(@PathVariable Long id) {
        return appUserRepository.findById(id)
                .orElseThrow(()-> new RuntimeException("${id} Not Found"));
    }

    @PutMapping(path = "/user/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR')")
    AppUser updateUser(@RequestBody AppUser newUser, @PathVariable Long id){
        return appUserRepository.findById(id)
                .map(user-> {
                    user.setName(newUser.getName());
                    user.setUsername(newUser.getUsername());
                    user.setEmail(newUser.getEmail());
                    return appUserRepository.save(user);
                }).orElseThrow(()-> new RuntimeException("${id} Not Found"));
    }


    @DeleteMapping(path = "/user/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR')")
    String deleteUser(@PathVariable Long id){
        if(!appUserRepository.existsById(id)){
            throw new RuntimeException("${id} Not Found");
        }
        appUserRepository.deleteById(id);
        return id + "has already been deleted";

    }
}
