package DataCenter.FullStack.Controller;


import DataCenter.FullStack.Model.Role;
import DataCenter.FullStack.Model.User;
import DataCenter.FullStack.Respository.RoleRepository;
import DataCenter.FullStack.Respository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(value = "*",maxAge = 3600)
public class AdminController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;


    @GetMapping(path = "/find/user")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR')")
    List<User> appUserList(){
        return userRepository.findAll();
    }



    @DeleteMapping(path = "/delete/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    String deleteUser(@PathVariable Long id ){
        if(!userRepository.existsById(id)){
            throw new RuntimeException("${id} Not Found");
        }
        userRepository.deleteById(id);
         return "Completed Delete";
    }
}
