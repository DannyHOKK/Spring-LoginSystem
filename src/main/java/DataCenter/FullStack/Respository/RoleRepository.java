package DataCenter.FullStack.Respository;

import DataCenter.FullStack.Model.ERole;
import DataCenter.FullStack.Model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role,Integer> {
    Optional<Role> findByName(ERole name);
}
